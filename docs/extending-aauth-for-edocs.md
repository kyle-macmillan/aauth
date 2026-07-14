author: Kyle

---
# Sentinel
How the sentinel sits into the AAuth protocol.

The AAuth protocol defines access server (AS) generically enough that we could call the sentinel an
AS. That said, eDocs introduces a new pattern where one AS must communicate with another AS before 
minting an auth token. This pattern isn't foreign to AAuth, however. AAuth already recognizes that a
single agent call might require communicating with a downstream resource. Thus, a resource may turn
into an agent to request a resource token from another resource. In the same way, the sentinel can
only partially authorize access, and must communicate with the resource controller to fully authorize. 


## Registration Overview
If there is no eDocs identifier in the resource token, sentinel should auto-reject unless the "register"
flag is set in the resource token. When this flag is marked, the sentinel should create a new entry in 
its eDoc mapping with the resource token aud set as the controller. The resource token can optionally 
include an eDoc id. That way controllers can create policies before the resource are requested. If that 
id is taken, the sentinel can communicate that to the AS. 

The sentinel must still communicate with the AS of the aud field. This is necessary if the controller has 
already established policies over that resource. 

## Sharing Overview
The sentinel acts as a broker between agents/PS and the ASes that control resource access. 
In AAuth, the PS talks directly with the AS listed in the resource token's aud field. For 
eDocs, the aud field will only serve to inform the PS of the controller, in case the PS 
pre-emptively refuses to allow agent to access resource, based on the controller, without talking 
to the sentinel. Absent such a policy, the PS will forward the resource token to the sentinel.

The sentinel will inspect the resource token and extract the id for the requested eDoc, the proposed
function, and the requesting entity. The sentinel will then check its internal state to determine 
which AS(es) to talk to, based on the id of the requested eDoc. 

The sentinel then sends the proposed dataflow to the appropriate AS(es), who will respond yes, no, or 
a conditional yes, if the access policy depends on global state held by the sentinel (e.g. the requester 
does also possess some other data). 

If all responses are eventually affirmative, the sentinel mints and sends an auth token to the PS
that requested the resource. 

## State 
The sentinel stores the global state of dataflows. In particular:
- The sentinel must maintain a map between eDoc IDs and their controller(s). An eDoc may have
multiple controllers if, e.g., the eDoc is the product of eDocs controller by different entities.
- The sentinel must maintain a graph of materialized dataflows. 

## API 
- Controllers should be able to request the provenance of an eDoc they can control. 
- Controllers should be able to delegate control rights to other entities. 
