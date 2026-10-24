"""Exact maximum-weight bipartite assignment (stdlib only).

The edge set is split into connected components (workflow runs only compete for requests whose
processing windows overlap, so components are small) and each component is solved optimally with
the Hungarian algorithm.  Rows/columns are sorted, so the result is deterministic and independent of
input order.
"""
from __future__ import annotations

from collections import defaultdict


def _hungarian(cost):
    """Min-cost assignment for an n x m matrix with n <= m. Returns row -> column."""
    n, m = len(cost), len(cost[0])
    INF = float("inf")
    u, v = [0.0] * (n + 1), [0.0] * (m + 1)
    p, way = [0] * (m + 1), [0] * (m + 1)
    for i in range(1, n + 1):
        p[0] = i
        j0 = 0
        minv = [INF] * (m + 1)
        used = [False] * (m + 1)
        while True:
            used[j0] = True
            i0, delta, j1 = p[j0], INF, 0
            for j in range(1, m + 1):
                if not used[j]:
                    cur = cost[i0 - 1][j - 1] - u[i0] - v[j]
                    if cur < minv[j]:
                        minv[j], way[j] = cur, j0
                    if minv[j] < delta:
                        delta, j1 = minv[j], j
            for j in range(m + 1):
                if used[j]:
                    u[p[j]] += delta
                    v[j] -= delta
                else:
                    minv[j] -= delta
            j0 = j1
            if p[j0] == 0:
                break
        while True:
            j1 = way[j0]
            p[j0] = p[j1]
            j0 = j1
            if j0 == 0:
                break
    return {p[j] - 1: j - 1 for j in range(1, m + 1) if p[j]}


def max_weight_assignment(edges: dict) -> dict:
    """edges: {(left, right): weight > 0}. Returns {left: right} maximising total weight, each left and
    each right used at most once (a left may stay unassigned)."""
    adj = defaultdict(set)
    for (a, b) in edges:
        adj[("L", a)].add(("R", b))
        adj[("R", b)].add(("L", a))
    seen, result = set(), {}
    for start in sorted(adj, key=repr):
        if start in seen:
            continue
        comp, stack = [], [start]
        seen.add(start)
        while stack:
            x = stack.pop()
            comp.append(x)
            for y in adj[x]:
                if y not in seen:
                    seen.add(y)
                    stack.append(y)
        lefts = sorted((x[1] for x in comp if x[0] == "L"), key=repr)
        rights = sorted((x[1] for x in comp if x[0] == "R"), key=repr)
        # each left also gets a private "stay unassigned" column with weight 0
        cols = rights + [("__none__", a) for a in lefts]
        big = max(edges.values()) + 1.0
        cost = [[big - edges[(a, c)] if (a, c) in edges else (big if isinstance(c, tuple) and c[0] == "__none__" and c[1] == a else 1e12)
                 for c in cols] for a in lefts]
        for i, j in _hungarian(cost).items():
            c = cols[j]
            if not (isinstance(c, tuple) and c[0] == "__none__") and (lefts[i], c) in edges:
                result[lefts[i]] = c
    return result
