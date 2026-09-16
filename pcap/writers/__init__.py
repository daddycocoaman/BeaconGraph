"""Graph writers, one per backend.

Both take the same ``(nodes, edges)`` lists from ``pcap.graph`` and differ only in how the
backend wants them: Neo4j multi-labels a node and batches with ``UNWIND``, ArcadeDB gives a
vertex exactly one type and needs its schema declared up front.
"""


def chunks(items, size):
    """Split a list into ``size``-row batches, preserving order.

    Shared because both writers batch the same way: one statement per chunk, with the rows
    travelling as a single query parameter rather than being interpolated.
    """
    for start in range(0, len(items), size):
        yield items[start:start + size]
