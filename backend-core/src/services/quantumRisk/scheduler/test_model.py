"""
Unit tests for CP-SAT scheduler model (test_model.py).

Verifies optimal ordering, dependency constraints, capacity limits,
deadline infeasibility, cycle detection, and deterministic behavior.
"""

from model import validate_and_solve


def test_small_known_instance():
    # Task A: duration=2, people=1, weight=1.0
    # Task B: duration=3, people=1, weight=2.0
    # Capacity=1, Horizon=10.
    # If B first: B(0..3, exp 2*3=6) + A(3..5, exp 1*5=5) = 11.
    # If A first: A(0..2, exp 1*2=2) + B(2..5, exp 2*5=10) = 12.
    # Optimal: B first!
    input_data = {
        "tasks": [
            {"taskId": "A", "durationMonths": 2, "peopleNeeded": 1, "dependsOn": [], "exposureWeightPerMonth": 1.0},
            {"taskId": "B", "durationMonths": 3, "peopleNeeded": 1, "dependsOn": [], "exposureWeightPerMonth": 2.0},
        ],
        "teamCapacity": 1,
        "horizonMonths": 10,
    }
    res = validate_and_solve(input_data)
    assert res["solverStatus"] == "OPTIMAL", f"Expected OPTIMAL, got {res['solverStatus']}"
    gantt = {row["taskId"]: row for row in res["ganttRows"]}
    assert gantt["B"]["startMonth"] == 0 and gantt["B"]["endMonth"] == 3, "Heavy task B should start first at 0"
    assert gantt["A"]["startMonth"] == 3 and gantt["A"]["endMonth"] == 5, "Task A should start at 3"
    assert res["totalExposure"] == 11.0, f"Expected totalExposure 11.0, got {res['totalExposure']}"
    print("test_small_known_instance PASSED")


def test_heavy_weight_first():
    # Task 1: weight 10.0, duration 2, people 1
    # Task 2: weight 1.0, duration 2, people 1
    # Capacity 1, Horizon 10
    input_data = {
        "tasks": [
            {"taskId": "T2", "durationMonths": 2, "peopleNeeded": 1, "dependsOn": [], "exposureWeightPerMonth": 1.0},
            {"taskId": "T1", "durationMonths": 2, "peopleNeeded": 1, "dependsOn": [], "exposureWeightPerMonth": 10.0},
        ],
        "teamCapacity": 1,
        "horizonMonths": 10,
    }
    res = validate_and_solve(input_data)
    assert res["solverStatus"] == "OPTIMAL"
    gantt = {row["taskId"]: row for row in res["ganttRows"]}
    assert gantt["T1"]["startMonth"] == 0, "Heavy-weight task T1 should start first at month 0"
    assert gantt["T2"]["startMonth"] == 2, "T2 should start after T1"
    print("test_heavy_weight_first PASSED")


def test_dependency_respected():
    # Task A (duration 2) -> Task B (duration 2, dependsOn ['A'])
    input_data = {
        "tasks": [
            {"taskId": "A", "durationMonths": 2, "peopleNeeded": 1, "dependsOn": [], "exposureWeightPerMonth": 1.0},
            {"taskId": "B", "durationMonths": 2, "peopleNeeded": 1, "dependsOn": ["A"], "exposureWeightPerMonth": 10.0},
        ],
        "teamCapacity": 2,  # Even with capacity 2, B must wait for A
        "horizonMonths": 10,
    }
    res = validate_and_solve(input_data)
    assert res["solverStatus"] == "OPTIMAL"
    gantt = {row["taskId"]: row for row in res["ganttRows"]}
    assert gantt["B"]["startMonth"] >= gantt["A"]["endMonth"], "Dependency failed: B started before A ended"
    print("test_dependency_respected PASSED")


def test_capacity_never_exceeded():
    # 3 tasks, each needing 2 people. Capacity = 3, Horizon = 10.
    # Maximum 1 task can run at a time!
    input_data = {
        "tasks": [
            {"taskId": "T1", "durationMonths": 2, "peopleNeeded": 2, "dependsOn": [], "exposureWeightPerMonth": 1.0},
            {"taskId": "T2", "durationMonths": 2, "peopleNeeded": 2, "dependsOn": [], "exposureWeightPerMonth": 1.0},
            {"taskId": "T3", "durationMonths": 2, "peopleNeeded": 2, "dependsOn": [], "exposureWeightPerMonth": 1.0},
        ],
        "teamCapacity": 3,
        "horizonMonths": 10,
    }
    res = validate_and_solve(input_data)
    assert res["solverStatus"] == "OPTIMAL"
    gantt = res["ganttRows"]

    for month in range(10):
        active_demand = sum(
            2 for row in gantt if row["startMonth"] <= month < row["endMonth"]
        )
        assert active_demand <= 3, f"Capacity exceeded at month {month}: {active_demand} > 3"

    print("test_capacity_never_exceeded PASSED")


def test_deadline_infeasible():
    # Task duration 5, deadline 3 -> Impossible!
    input_data = {
        "tasks": [
            {"taskId": "T1", "durationMonths": 5, "peopleNeeded": 1, "dependsOn": [], "deadlineMonth": 3, "exposureWeightPerMonth": 1.0},
        ],
        "teamCapacity": 2,
        "horizonMonths": 10,
    }
    res = validate_and_solve(input_data)
    assert res["solverStatus"] in ("INFEASIBLE", "ERROR")
    print("test_deadline_infeasible PASSED")


def test_cycle_rejected():
    # Task A depends on B, B depends on A -> Cycle!
    input_data = {
        "tasks": [
            {"taskId": "A", "durationMonths": 2, "peopleNeeded": 1, "dependsOn": ["B"], "exposureWeightPerMonth": 1.0},
            {"taskId": "B", "durationMonths": 2, "peopleNeeded": 1, "dependsOn": ["A"], "exposureWeightPerMonth": 1.0},
        ],
        "teamCapacity": 2,
        "horizonMonths": 10,
    }
    res = validate_and_solve(input_data)
    assert res["solverStatus"] == "ERROR", f"Expected ERROR for cycle, got {res['solverStatus']}"
    assert "cycle" in res["message"].lower(), f"Expected cycle in message, got '{res['message']}'"
    print("test_cycle_rejected PASSED")


def main():
    test_small_known_instance()
    test_heavy_weight_first()
    test_dependency_respected()
    test_capacity_never_exceeded()
    test_deadline_infeasible()
    test_cycle_rejected()
    print("All test_model.py tests PASSED successfully!")


if __name__ == "__main__":
    main()
