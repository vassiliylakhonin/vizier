# Validation metrics

The v0.1 product question is whether developers put Vizier before actions that
their agents actually execute.

The primary metric is verified agent actions per day. Sign-ups and one-off curl
requests do not answer the question.

The founder-supplied problem/solution fit targets are:

- 10 independent production integrations
- at least 5 still active after 30 days
- more than 10,000 authorization calls per day
- repeated machine-generated calls
- at least 2 users willing to pay

No target has been achieved or tested. The current implementation has no
durable metrics store. Structured logs expose the fields needed to calculate
call count and decision mix later. Counting unique agents, repeat use, and calls
per integration requires authenticated integration IDs before a public pilot.

