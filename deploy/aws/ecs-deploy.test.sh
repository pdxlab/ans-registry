#!/usr/bin/env bash
# Tests for the pure parts of ecs-deploy.sh (no AWS calls).
# Run: bash deploy/aws/ecs-deploy.test.sh
set -euo pipefail
cd "$(dirname "$0")"

export CLUSTER=test-cluster IMAGE="123.dkr.ecr.us-east-1.amazonaws.com/repo@sha256:abc"
# shellcheck source=ecs-deploy.sh
source ./ecs-deploy.sh

failures=0
check() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "ok   - $name"
  else
    echo "FAIL - $name"
    echo "       expected: $expected"
    echo "       actual:   $actual"
    failures=$((failures + 1))
  fi
}

describe_td() {
  # $1 = containerDefinitions JSON
  jq -n --argjson containers "$1" '{
    taskDefinition: {
      taskDefinitionArn: "arn:aws:ecs:us-east-1:123:task-definition/app:7",
      family: "app", revision: 7, status: "ACTIVE",
      taskRoleArn: "arn:aws:iam::123:role/task", executionRoleArn: "arn:aws:iam::123:role/exec",
      networkMode: "awsvpc", requiresCompatibilities: ["FARGATE"], cpu: "1024", memory: "2048",
      containerDefinitions: $containers, volumes: [], placementConstraints: [],
      compatibilities: ["EC2", "FARGATE"], requiresAttributes: [{name: "x"}],
      registeredAt: "2026-09-22T00:00:00Z", registeredBy: "arn:aws:iam::123:role/iac"
    },
    tags: [{key: "owner", value: "iac"}]
  }'
}

# --- render_revision ---------------------------------------------------------

single=$(describe_td '[{"name":"whatever","image":"old","environment":[{"name":"A","value":"1"}],"secrets":[{"name":"S","valueFrom":"arn:x"}]}]')
out=$(render_revision "$single" app)
check "swaps the image of a single container" "$IMAGE" "$(jq -r '.containerDefinitions[0].image' <<<"$out")"
check "keeps env and secret references" '[{"name":"A","value":"1"}]|[{"name":"S","valueFrom":"arn:x"}]' \
  "$(jq -c '.containerDefinitions[0].environment' <<<"$out")|$(jq -c '.containerDefinitions[0].secrets' <<<"$out")"
check "keeps roles and sizing" "arn:aws:iam::123:role/task arn:aws:iam::123:role/exec 1024 2048" \
  "$(jq -r '"\(.taskRoleArn) \(.executionRoleArn) \(.cpu) \(.memory)"' <<<"$out")"
check "drops output-only fields" "[]" \
  "$(jq -c '[keys[] | select(. == "taskDefinitionArn" or . == "revision" or . == "status" or . == "compatibilities" or . == "requiresAttributes" or . == "registeredAt" or . == "registeredBy")]' <<<"$out")"
check "carries tags over" '[{"key":"owner","value":"iac"}]' "$(jq -c '.tags' <<<"$out")"

sidecar=$(describe_td '[{"name":"otel","image":"adot"},{"name":"app","image":"old"}]')
out=$(render_revision "$sidecar" app)
check "with a sidecar, swaps only the container named after the family" "adot $IMAGE" \
  "$(jq -r '[.containerDefinitions[].image] | join(" ")' <<<"$out")"

ambiguous=$(describe_td '[{"name":"one","image":"a"},{"name":"two","image":"b"}]')
if render_revision "$ambiguous" app >/dev/null 2>&1; then
  check "rejects several containers with none named after the family" "error" "rendered"
else
  check "rejects several containers with none named after the family" "error" "error"
fi

untagged=$(describe_td '[{"name":"app","image":"old"}]' | jq 'del(.tags)')
check "omits tags when there are none" "false" "$(render_revision "$untagged" app | jq 'has("tags")')"

# --- deployment_state --------------------------------------------------------

NEW="arn:aws:ecs:us-east-1:123:task-definition/app:8"
OLD="arn:aws:ecs:us-east-1:123:task-definition/app:7"
svc() { jq -n --argjson d "$1" '{services: [{deployments: $d}]}'; }

check "our revision not visible yet → pending" "pending" \
  "$(deployment_state "$(svc "[{\"status\":\"PRIMARY\",\"taskDefinition\":\"$OLD\",\"rolloutState\":\"COMPLETED\"}]")" "$NEW")"
check "ours primary and rolling → in_progress" "in_progress" \
  "$(deployment_state "$(svc "[{\"status\":\"PRIMARY\",\"taskDefinition\":\"$NEW\",\"rolloutState\":\"IN_PROGRESS\"},{\"status\":\"ACTIVE\",\"taskDefinition\":\"$OLD\"}]")" "$NEW")"
check "ours primary and done → completed" "completed" \
  "$(deployment_state "$(svc "[{\"status\":\"PRIMARY\",\"taskDefinition\":\"$NEW\",\"rolloutState\":\"COMPLETED\"}]")" "$NEW")"
check "ours marked failed → failed" "failed" \
  "$(deployment_state "$(svc "[{\"status\":\"ACTIVE\",\"taskDefinition\":\"$NEW\",\"rolloutState\":\"FAILED\"},{\"status\":\"PRIMARY\",\"taskDefinition\":\"$OLD\",\"rolloutState\":\"IN_PROGRESS\"}]")" "$NEW")"
check "circuit breaker put the old revision back → rolled_back" "rolled_back" \
  "$(deployment_state "$(svc "[{\"status\":\"INACTIVE\",\"taskDefinition\":\"$NEW\"},{\"status\":\"PRIMARY\",\"taskDefinition\":\"$OLD\",\"rolloutState\":\"COMPLETED\"}]")" "$NEW")"

# --- render_schedule ---------------------------------------------------------

schedule='{
  "Arn": "arn:aws:scheduler:us-east-1:123:schedule/default/job",
  "CreationDate": "2026-09-22T00:00:00Z", "LastModificationDate": "2026-09-22T00:00:00Z",
  "Name": "job", "GroupName": "default", "State": "DISABLED",
  "ScheduleExpression": "cron(*/5 * ? * * *)", "ScheduleExpressionTimezone": "UTC",
  "FlexibleTimeWindow": {"Mode": "OFF"},
  "Target": {"Arn": "arn:aws:ecs:us-east-1:123:cluster/c", "RoleArn": "arn:aws:iam::123:role/sched",
             "EcsParameters": {"TaskDefinitionArn": "arn:aws:ecs:us-east-1:123:task-definition/job:1", "LaunchType": "FARGATE"}}
}'
out=$(render_schedule "$schedule" "arn:aws:ecs:us-east-1:123:task-definition/job:2")
check "points the schedule at the new revision" "arn:aws:ecs:us-east-1:123:task-definition/job:2" \
  "$(jq -r '.Target.EcsParameters.TaskDefinitionArn' <<<"$out")"
check "keeps state, cron, role and launch type" 'DISABLED|cron(*/5 * ? * * *)|arn:aws:iam::123:role/sched|FARGATE' \
  "$(jq -r '"\(.State)|\(.ScheduleExpression)|\(.Target.RoleArn)|\(.Target.EcsParameters.LaunchType)"' <<<"$out")"
check "drops output-only fields" "false false false" \
  "$(jq -r '"\(has("Arn")) \(has("CreationDate")) \(has("LastModificationDate"))"' <<<"$out")"

# --- update_schedules --------------------------------------------------------

# A separate bash, so `set -e` behaves as it does in a real run.
denied=$(bash -c '
  source ./ecs-deploy.sh
  aws() { echo "AccessDeniedException" >&2; return 254; }
  declare -A arns=([job]="arn:aws:ecs:us-east-1:123:task-definition/job:2")
  update_schedules arns
  echo "continued after a failed listing"
' 2>&1) && rc=0 || rc=$?
check "stops when the schedules can't be listed" "1 no" \
  "$rc $(grep -q 'continued after' <<<"$denied" && echo yes || echo no)"

echo
if ((failures > 0)); then
  echo "$failures test(s) failed"
  exit 1
fi
echo "all tests passed"
