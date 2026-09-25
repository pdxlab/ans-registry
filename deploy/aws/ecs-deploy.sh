#!/usr/bin/env bash
# Roll one container image out to an ECS service and the job task definitions
# that run the same image.
#
# Each task definition is re-registered from its latest ACTIVE revision with
# only the image changed. Env vars, secret references, roles and sizing stay as
# the infrastructure defined them.
#
# Order, so a failure leaves prod on the old image:
#   1. register the service's new revision
#   2. MIGRATE_COMMAND (optional) as a one-off Fargate task on that revision
#   3. update the service and wait until the new revision is serving
#   4. register new revisions of JOB_FAMILIES
#   5. repoint EventBridge schedules that target those families
#
# Required env:
#   CLUSTER          ECS cluster name
#   IMAGE            image to deploy, ideally pinned by digest (repo@sha256:...)
# Optional env:
#   SERVICE          ECS service to roll
#   JOB_FAMILIES     space-separated task definition families for this image
#   MIGRATE_COMMAND  JSON array, e.g. ["python","manage.py","migrate","--no-input"]
#   WAIT_TIMEOUT_S   how long to wait for the service rollout (default 900)
#   REPOINT_SCHEDULES  "false" skips step 5, for job families that no schedule
#                    runs (default "true")
set -euo pipefail

: "${CLUSTER:?CLUSTER is required}"
: "${IMAGE:?IMAGE is required}"
SERVICE="${SERVICE:-}"
JOB_FAMILIES="${JOB_FAMILIES:-}"
MIGRATE_COMMAND="${MIGRATE_COMMAND:-}"
WAIT_TIMEOUT_S="${WAIT_TIMEOUT_S:-900}"
REPOINT_SCHEDULES="${REPOINT_SCHEDULES:-true}"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"

log() { echo "==> $*"; }
fail() { echo "::error::$*"; exit 1; }

# Only fields RegisterTaskDefinition accepts. Anything else describe returns
# (arn, revision, status, registeredAt, ...) is output-only.
REGISTER_FIELDS='["family","taskRoleArn","executionRoleArn","networkMode",
  "containerDefinitions","volumes","placementConstraints",
  "requiresCompatibilities","cpu","memory","pidMode","ipcMode",
  "proxyConfiguration","inferenceAccelerators","ephemeralStorage",
  "runtimePlatform","enableFaultInjection"]'

# The container that runs the image: the only one, or the one named after the
# family when there are sidecars.
# shellcheck disable=SC2016  # a jq program; $names/$family are jq variables
CONTAINER_INDEX='
  (.containerDefinitions | map(.name)) as $names
  | if ($names | length) == 1 then 0 else ($names | index($family)) end'

# render_revision <describe-task-definition JSON> <family>
# Prints register-task-definition input with the image swapped.
render_revision() {
  jq -e --arg image "$IMAGE" --arg family "$2" --argjson fields "$REGISTER_FIELDS" "
    .taskDefinition as \$td
    | (\$td | $CONTAINER_INDEX) as \$i
    | if \$i == null then
        error(\"task definition \(\$family) has several containers and none is named \(\$family)\")
      else . end
    | (\$td | .containerDefinitions[\$i].image = \$image
            | with_entries(select(.key as \$k | \$fields | index(\$k)))
            | with_entries(select(.value != null)))
      + (if (.tags // []) | length > 0 then {tags: .tags} else {} end)
  " <<<"$1"
}

# register_revision <family>  → prints the new task definition ARN
register_revision() {
  local current input
  current=$(aws ecs describe-task-definition --task-definition "$1" --include TAGS --output json)
  input=$(render_revision "$current" "$1")
  aws ecs register-task-definition --cli-input-json "$input" \
    --query 'taskDefinition.taskDefinitionArn' --output text
}

container_name() {
  aws ecs describe-task-definition --task-definition "$1" --output json |
    jq -r --arg family "$2" ".taskDefinition | ($CONTAINER_INDEX) as \$i | .containerDefinitions[\$i].name"
}

run_migration() {
  local td_arn="$1" family="$2" container network task_arn task exit_code
  container=$(container_name "$td_arn" "$family")
  network=$(aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" \
    --query 'services[0].networkConfiguration' --output json)
  log "Running migrations on $td_arn: $MIGRATE_COMMAND"
  task_arn=$(aws ecs run-task \
    --cluster "$CLUSTER" \
    --task-definition "$td_arn" \
    --launch-type FARGATE \
    --network-configuration "$network" \
    --started-by "gha-migrate-${GITHUB_RUN_ID:-local}" \
    --overrides "$(jq -nc --arg name "$container" --argjson cmd "$MIGRATE_COMMAND" \
        '{containerOverrides: [{name: $name, command: $cmd}]}')" \
    --query 'tasks[0].taskArn' --output text)
  [[ -n "$task_arn" && "$task_arn" != "None" ]] || fail "migration task did not start"

  aws ecs wait tasks-stopped --cluster "$CLUSTER" --tasks "$task_arn"
  task=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$task_arn" --output json)
  exit_code=$(jq -r --arg name "$container" \
    '.tasks[0].containers[] | select(.name == $name) | .exitCode // "none"' <<<"$task")

  print_task_logs "$td_arn" "$container" "$task_arn"
  if [[ "$exit_code" != "0" ]]; then
    fail "migration task $task_arn exited $exit_code ($(jq -r '.tasks[0].stoppedReason // ""' <<<"$task"))"
  fi
  log "Migrations finished"
}

print_task_logs() {
  local td_arn="$1" container="$2" task_arn="$3" group prefix
  read -r group prefix < <(aws ecs describe-task-definition --task-definition "$td_arn" --output json |
    jq -r --arg name "$container" '.taskDefinition.containerDefinitions[] | select(.name == $name)
      | .logConfiguration | select(.logDriver == "awslogs") | .options
      | "\(.["awslogs-group"]) \(.["awslogs-stream-prefix"])"') || true
  [[ -n "${group:-}" && -n "${prefix:-}" ]] || return 0
  echo "--- last log lines of $task_arn"
  aws logs get-log-events --log-group-name "$group" \
    --log-stream-name "$prefix/$container/${task_arn##*/}" \
    --limit 100 --query 'events[].message' --output text 2>/dev/null | tr '\t' '\n' || true
  echo "---"
}

# deployment_state <describe-services JSON> <task definition ARN>
# Prints one of: pending, in_progress, completed, failed, rolled_back.
# The deployment circuit breaker can roll a service back to the old revision,
# which also ends "stable", so judge by what happened to our deployment.
deployment_state() {
  jq -r --arg td "$2" '
    .services[0].deployments as $deployments
    | ($deployments | map(select(.taskDefinition == $td)) | first) as $ours
    | if $ours == null then "pending"
      elif $ours.rolloutState == "FAILED" then "failed"
      elif $ours.status != "PRIMARY" then "rolled_back"
      elif $ours.rolloutState == "COMPLETED" then "completed"
      else "in_progress" end' <<<"$1"
}

wait_for_service() {
  local td_arn="$1" deadline=$((SECONDS + WAIT_TIMEOUT_S)) svc state event
  while :; do
    svc=$(aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" --output json)
    state=$(deployment_state "$svc" "$td_arn")
    event=$(jq -r '.services[0].events[0].message // ""' <<<"$svc")
    case "$state" in
      completed)
        if [[ "$(jq -r '.services[0].desiredCount' <<<"$svc")" == "0" ]]; then
          echo "::warning::$SERVICE has desiredCount 0: the new revision is deployed but no task is running."
        fi
        log "Service $SERVICE is serving $td_arn"
        return 0 ;;
      failed) fail "rollout of $td_arn on $SERVICE failed: $event" ;;
      rolled_back) fail "$SERVICE rolled back from $td_arn: $event" ;;
    esac
    if ((SECONDS >= deadline)); then
      fail "timed out after ${WAIT_TIMEOUT_S}s waiting for $SERVICE ($state): $event"
    fi
    sleep 15
  done
}

# Repoint every schedule whose target is one of the given families at its new
# revision. update-schedule replaces the whole schedule, so send it back as-is
# with only the task definition changed (state, cron and retry are kept).
update_schedules() {
  local -n new_arns="$1"
  local listing group name current family
  # Fetched up front: a failure inside the `< <(...)` below would not stop
  # the script, and the schedules would silently stay on the old revision.
  listing=$(aws scheduler list-schedules --output json) ||
    fail "could not list EventBridge schedules, so none were repointed"
  while read -r group name; do
    [[ -n "$name" ]] || continue
    current=$(aws scheduler get-schedule --group-name "$group" --name "$name" --output json)
    family=$(jq -r '.Target.EcsParameters.TaskDefinitionArn // "" | split("/")[-1] | split(":")[0]' <<<"$current")
    [[ -n "$family" && -n "${new_arns[$family]:-}" ]] || continue
    log "Schedule $name → ${new_arns[$family]}"
    aws scheduler update-schedule \
      --cli-input-json "$(render_schedule "$current" "${new_arns[$family]}")" \
      --output text >/dev/null
  done < <(jq -r '.Schedules[] | "\(.GroupName) \(.Name)"' <<<"$listing")
}

# render_schedule <get-schedule JSON> <task definition ARN>
# update-schedule input: the same schedule minus output-only fields.
render_schedule() {
  jq --arg arn "$2" '
    del(.Arn, .CreationDate, .LastModificationDate)
    | .Target.EcsParameters.TaskDefinitionArn = $arn' <<<"$1"
}

main() {
  echo "### ECS deploy" >>"$SUMMARY"
  echo "- Image: \`$IMAGE\`" >>"$SUMMARY"

  if [[ -n "$SERVICE" ]]; then
    local family td_arn
    family=$(aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" \
      --query 'services[0].taskDefinition' --output text | sed 's#.*/##; s#:[0-9]*$##')
    [[ -n "$family" && "$family" != "None" ]] || fail "service $SERVICE not found in $CLUSTER"
    td_arn=$(register_revision "$family")
    log "Registered $td_arn"
    if [[ -n "$MIGRATE_COMMAND" ]]; then
      run_migration "$td_arn" "$family"
    fi
    aws ecs update-service --cluster "$CLUSTER" --service "$SERVICE" \
      --task-definition "$td_arn" --output text --query 'service.serviceName' >/dev/null
    wait_for_service "$td_arn"
    echo "- Service \`$SERVICE\` → \`${td_arn##*/}\`" >>"$SUMMARY"
  fi

  if [[ -n "$JOB_FAMILIES" ]]; then
    declare -A job_arns=()
    local job
    for job in $JOB_FAMILIES; do
      job_arns[$job]=$(register_revision "$job")
      log "Registered ${job_arns[$job]}"
      echo "- Job \`${job_arns[$job]##*/}\`" >>"$SUMMARY"
    done
    if [[ "$REPOINT_SCHEDULES" == "true" ]]; then
      update_schedules job_arns
    fi
  fi
}

# Sourcing the file (for tests) loads the functions without deploying.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
