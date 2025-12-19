Office Bakery — Multithreaded Simulation (C)

Overview
- 4 chefs (threads)
- Customers are threads
- Sofa with 4 seats (reserved from sit until after payment is accepted)
- Shop capacity is 25 customers at once; new arrivals beyond capacity do not enter
- Single cash register; chefs prioritize accepting payments over baking
- Up to 4 concurrent bakes (one per chef)

Input
Lines of the form:
  <time_stamp> Customer <id>
Terminate with:
  <EOF>

Output
Lines of the form:
  <time_stamp> <Customer/Chef> <id> <action>

Timing
- Real seconds map to input timestamps relative to the earliest timestamp.
- Durations:
  - Customer: enter 1s, sit 1s, pay 1s
  - Chef: bake 2s, accept payment 2s
- “requests cake” is logged when a chef starts baking that customer; the paired
  “bakes for Customer <id>” is printed at the same timestamp.

Build
  gcc -O2 -pthread -o bakery bakery.c

Run
  ./bakery < input.txt

Notes
- Sofa seats are FIFO for service. Standing customers are FIFO for promotion to a seat when a seat frees.
- A seat is reserved from when it’s assigned (customer begins the sit action) until the customer leaves after payment acceptance.
- Chefs always prioritize accepting payments (single register) before baking new cakes.
