author: Kyle

---

# Resource
The resource server in eDocs will need to be re-architected to support server-side / TEE-side
computation over resources. With traditional AAuth, agents request access to a resource. Here,
agents may optionally request the result of a transformed resource. Thus, we need to decide where
and who perform this computation. 

A first option is at the resource. The is simplest and where we should start. The downside is agent
maliciously requesting resources (imagine a DoS/DDoS). One solution is blacklisting bad agents,
which, because they are tied to a person server (unlike IP addresses) seems like a better solution.
Alternatively, agents and resources could use the x402 protocol, which requires agents to pay to
access resources. 

## Resource Token
- Resource token must include either the eDoc id or populate the Register flag. We will need to extend 
the current resource token schema to include an optional Register flag. The resource controller can
include both some eDoc Id and Register flag. That way, resource controllers can start to create
policies before registering an eDoc. 
- The aud field should now be a list of the ASes believed to be controllers. There may be multiple
controllers if the requested resource is derived from other resources controlled by different
actors. 

# Person Server
- Person servers should always forward the resource token to the sentinel, as opposed to the named 
ASes in the resource token aud field. 
- Person servers can still deny access based on the aud field without contacting the sentinel. 

# Access Server
- Access servers (other than the sentinel) don't mint auth tokens anymore. Instead, the sentinel
will forward the resource token to the appropriate access servers. The ASes proceed as usual,
evaluating the resource token against their policies. ASes can accept/reject as usual. Because we
want eDocs to support conditional policies, ASes can also submit conditional acceptances that depend
on global state held by the sentinel. 

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


