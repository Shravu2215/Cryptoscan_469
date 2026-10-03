"""
CP-SAT Migration Task Scheduling Model (Feature 2).

Standalone OR-Tools CP-SAT solver script.
Reads a ScheduleInput JSON from stdin and outputs a ScheduleResult JSON to stdout.

Supports capacity, dependency, deadline, and horizon constraints while
minimizing total exposure weight over time.
"""

import sys
import json
from ortools.sat.python import cp_model


def error_response(msg):
    return {
        "solverStatus": "ERROR",
        "waves": [],
        "ganttRows": [],
        "totalExposure": 0.0,
        "message": str(msg),
    }


def infeasible_response(msg):
    return {
        "solverStatus": "INFEASIBLE",
        "waves": [],
        "ganttRows": [],
        "totalExposure": 0.0,
        "message": str(msg),
    }


def detect_cycle(tasks_dict):
    """
    Detect dependency cycle or unknown task reference using Kahn's algorithm.
    Returns True if a cycle or invalid dependency exists, False if valid DAG.
    """
    in_degree = {t_id: 0 for t_id in tasks_dict}
    graph = {t_id: [] for t_id in tasks_dict}

    for t_id, t in tasks_dict.items():
        for dep in t["dependsOn"]:
            if dep not in tasks_dict:
                return True
            graph[dep].append(t_id)
            in_degree[t_id] += 1

    queue = [t_id for t_id, deg in in_degree.items() if deg == 0]
    visited_count = 0

    while queue:
        curr = queue.pop(0)
        visited_count += 1
        for nxt in graph[curr]:
            in_degree[nxt] -= 1
            if in_degree[nxt] == 0:
                queue.append(nxt)

    return visited_count < len(tasks_dict)


def validate_and_solve(input_data):
    if not isinstance(input_data, dict):
        return error_response("Input payload must be a JSON object")

    tasks_raw = input_data.get("tasks")
    if not isinstance(tasks_raw, list) or len(tasks_raw) == 0:
        return error_response("Input must contain a non-empty 'tasks' array")
    if len(tasks_raw) > 500:
        return error_response("Task count exceeds maximum limit of 500 tasks")

    horizon = input_data.get("horizonMonths")
    if horizon is None or not isinstance(horizon, (int, float)) or horizon < 1:
        return error_response("horizonMonths must be an integer >= 1")
    horizon = int(horizon)

    capacity = input_data.get("teamCapacity")
    if capacity is None:
        capacity = input_data.get("teamCapacityPerMonth")
    if capacity is None or not isinstance(capacity, (int, float)) or capacity < 0:
        return error_response("teamCapacity must be an integer >= 0")
    capacity = int(capacity)

    time_limit = input_data.get("timeLimitSeconds", 10)
    if not isinstance(time_limit, (int, float)) or time_limit <= 0:
        time_limit = 10

    # Parse and validate tasks
    tasks = []
    task_ids = set()

    for idx, t_raw in enumerate(tasks_raw):
        if not isinstance(t_raw, dict):
            return error_response(f"Task at index {idx} must be an object")

        t_id = t_raw.get("taskId") or t_raw.get("id")
        if not t_id or not isinstance(t_id, str):
            return error_response(f"Task at index {idx} missing valid taskId")
        if t_id in task_ids:
            return error_response(f"Duplicate taskId: '{t_id}'")
        task_ids.add(t_id)

        duration = t_raw.get("durationMonths")
        if duration is None:
            duration = t_raw.get("duration")
        if duration is None or not isinstance(duration, (int, float)) or duration < 1:
            return error_response(f"Task '{t_id}' durationMonths must be an integer >= 1")
        duration = int(duration)

        people = t_raw.get("peopleNeeded")
        if people is None:
            people = t_raw.get("effortPersonDays")
            if people is None:
                people = 0
        if not isinstance(people, (int, float)) or people < 0:
            return error_response(f"Task '{t_id}' peopleNeeded must be >= 0")
        people = int(people)

        if people > capacity:
            return error_response(f"Task '{t_id}' peopleNeeded ({people}) exceeds teamCapacity ({capacity})")

        deps = t_raw.get("dependsOn") or t_raw.get("depends_on") or []
        if not isinstance(deps, list):
            return error_response(f"Task '{t_id}' dependsOn must be a list")

        deadline = t_raw.get("deadlineMonth")
        if deadline is None:
            deadline = t_raw.get("deadline")
        if deadline is not None:
            if not isinstance(deadline, (int, float)) or deadline < 1:
                return error_response(f"Task '{t_id}' deadlineMonth must be >= 1")
            deadline = int(deadline)
            if deadline < duration:
                return error_response(f"Task '{t_id}' deadlineMonth ({deadline}) is less than duration ({duration})")

        exposure_weight = t_raw.get("exposureWeightPerMonth")
        if exposure_weight is None:
            exposure_weight = t_raw.get("exposureWeight", 0.0)
        if not isinstance(exposure_weight, (int, float)) or exposure_weight < 0:
            return error_response(f"Task '{t_id}' exposureWeightPerMonth must be >= 0")
        exposure_weight = float(exposure_weight)

        tasks.append({
            "taskId": t_id,
            "durationMonths": duration,
            "peopleNeeded": people,
            "dependsOn": deps,
            "deadlineMonth": deadline,
            "exposureWeightPerMonth": exposure_weight,
        })

    tasks_dict = {t["taskId"]: t for t in tasks}

    # Validate dependency references
    for t in tasks:
        for dep in t["dependsOn"]:
            if dep not in tasks_dict:
                return error_response(f"Task '{t['taskId']}' depends on unknown taskId: '{dep}'")

    # Validate dependency cycle
    if detect_cycle(tasks_dict):
        return error_response("Dependency cycle detected among tasks")

    # Solve using CP-SAT
    return solve_cpsat(tasks, capacity, horizon, time_limit)


def solve_cpsat(tasks, capacity, horizon, time_limit):
    model = cp_model.CpModel()

    start_vars = {}
    end_vars = {}
    interval_vars = {}
    demands = []
    intervals = []

    for t in tasks:
        t_id = t["taskId"]
        duration = t["durationMonths"]
        people = t["peopleNeeded"]
        deadline = t["deadlineMonth"]

        max_start = horizon - duration
        if max_start < 0:
            return infeasible_response(f"Horizon ({horizon}) is too short for task '{t_id}' duration ({duration})")

        start_var = model.NewIntVar(0, max_start, f"start_{t_id}")
        end_var = model.NewIntVar(duration, horizon, f"end_{t_id}")
        interval_var = model.NewIntervalVar(start_var, duration, end_var, f"interval_{t_id}")

        start_vars[t_id] = start_var
        end_vars[t_id] = end_var
        interval_vars[t_id] = interval_var

        if people > 0:
            intervals.append(interval_var)
            demands.append(people)

        if deadline is not None:
            model.Add(end_var <= deadline)

    # Dependency constraints
    for t in tasks:
        t_id = t["taskId"]
        for dep_id in t["dependsOn"]:
            model.Add(start_vars[t_id] >= end_vars[dep_id])

    # Cumulative capacity constraint
    if intervals and capacity > 0:
        model.AddCumulative(intervals, demands, capacity)

    # Objective: minimize sum(exposureWeightPerMonth * end)
    objective_terms = []
    for t in tasks:
        t_id = t["taskId"]
        weight = t["exposureWeightPerMonth"]
        scaled_weight = int(round(weight * 1000))
        if scaled_weight != 0:
            objective_terms.append(scaled_weight * end_vars[t_id])

    if objective_terms:
        model.Minimize(sum(objective_terms))

    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = float(time_limit)
    solver.parameters.num_search_workers = 1  # Fixed for determinism
    solver.parameters.random_seed = 42

    status = solver.Solve(model)

    if status in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        solver_status = "OPTIMAL" if status == cp_model.OPTIMAL else "FEASIBLE"

        gantt_rows = []
        for t in tasks:
            t_id = t["taskId"]
            s_val = int(solver.Value(start_vars[t_id]))
            e_val = int(solver.Value(end_vars[t_id]))
            gantt_rows.append({
                "taskId": t_id,
                "startMonth": s_val,
                "endMonth": e_val,
            })

        # Group tasks into waves by startMonth
        waves_dict = {}
        for row in gantt_rows:
            sm = row["startMonth"]
            if sm not in waves_dict:
                waves_dict[sm] = []
            waves_dict[sm].append(row)

        sorted_start_months = sorted(waves_dict.keys())
        waves = []
        for idx, sm in enumerate(sorted_start_months, 1):
            wave_tasks = waves_dict[sm]
            max_end = max(row["endMonth"] for row in wave_tasks)
            task_ids = [row["taskId"] for row in wave_tasks]
            waves.append({
                "wave": idx,
                "startMonth": sm,
                "endMonth": max_end,
                "taskIds": task_ids,
            })

        total_exposure = sum(t["exposureWeightPerMonth"] * solver.Value(end_vars[t["taskId"]]) for t in tasks)

        return {
            "solverStatus": solver_status,
            "waves": waves,
            "ganttRows": gantt_rows,
            "totalExposure": float(round(total_exposure, 4)),
            "message": "Schedule computed successfully",
        }
    else:
        return infeasible_response("No feasible schedule found satisfying all constraints and horizon")


def main():
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            result = error_response("Empty input received on stdin")
        else:
            try:
                input_data = json.loads(raw_input)
                result = validate_and_solve(input_data)
            except json.JSONDecodeError as e:
                result = error_response(f"Invalid JSON input: {str(e)}")
    except Exception as e:
        result = error_response(f"Unexpected error: {str(e)}")

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()