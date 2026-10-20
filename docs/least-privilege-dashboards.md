# Least-Privilege Dashboard and Access Model

A SIEM is only as safe as the access model around it. Detections tell you
what happened; the access model decides who can see and change that, and
getting it wrong turns a security tool into its own exposure. This note
describes the role model this lab assumes, kept deliberately simple.

## Roles

**Analyst (read-only).** The people who watch the fleet day to day. They
get read access to operations dashboards: fleet health, alert volume,
failed-login trends. They can filter and drill into alerts, but they
cannot edit detections, dashboards, or saved searches, and they cannot
reach raw data outside their assigned scope. This is the default role for
student workers and junior staff.

**Engineer (scoped write).** Owns detections and dashboards. Can author
and tune rules, create and share dashboards, and schedule exports. Write
access is held by the smallest possible group, and changes are reviewed.

**Administrator (platform).** Manages the platform itself: index access,
user and role assignment, retention. Separated from the engineer role so
that authoring a detection does not require platform administration.

## Scoping

Visibility is scoped by asset group. Each team or faculty group sees its
own systems, not the whole environment. An analyst assigned to one group
cannot enumerate another group's hosts or users through the dashboards.
This keeps a compromised or over-curious low-privilege account from
mapping the entire estate.

## Principles

1. Read-only by default. Write and admin are grants, not starting points.
2. One capability per role. Authoring detections and administering the
   platform are different jobs with different risks.
3. Scope every view. A dashboard should answer "how are my systems," not
   "show me everything."
4. Prefer a scoped self-service grant over a per-change ticket. Locking a
   SIEM down so tightly that every tuning change needs a ticket slows the
   people doing the monitoring; the fix is a correctly scoped permission,
   not looser access.

## Mapping to this lab

The detections in this repository are the Engineer-authored artifacts. The
evaluation report (`data/report.html`) is an Analyst-facing, read-only
view: it shows outcomes without exposing the raw event store or the
labels. Nothing in the read-only path can change a rule or reach data
outside its scope.
