---
title: Your AWS Permissions Shouldn't Leave the Room: An Offline Security Review Built on Gemma 2 2B
published: false
description: A small startup needs its AWS access checked but can't send its setup to a cloud AI. So I built an auditor that runs with the Wi-Fi off, and learned why a green checkmark isn't the product.
tags: devchallenge, hf26challenge, gemma, security
---

*This is a submission for the [Hacktoberfest Open-Source AI Challenge Week 2: Side Hustle](https://dev.to/challenges/hacktoberfest-week2-2026-10-12)*

Meet Ada. She's the CTO of a six-person fintech startup. (She's made up, but if you've worked at a startup, you've met her.)

Her team ships on AWS fast, and nobody's job is security. She knows their permissions are messy. Somewhere in there is a role that can do far more than it should, and she can't say which one.

She has three options: hire a security firm she can't afford, paste her AWS setup into a cloud chatbot and hope nobody minds, or ignore it until something breaks.

I just graduated in cybersecurity, and I want to be her fourth option. This post is about the tool I built to make that offer, and about the three times it told me everything was fine when it wasn't.

## What I Built

**First, the problem in plain terms.** Picture an AWS account as an office building. IAM policies are the keycards: they decide who can open which doors. Most cloud breaches don't involve anyone breaking a door down. Someone simply holds a keycard that opens far more than it should. In a policy, a `*` is a master key.

**ZeroLeak AI** reviews those keycards entirely on a laptop. No cloud AI, no API keys, and no internet once it's set up. You give it one policy, or a whole Terraform plan (the blueprint a team uses to build their AWS setup), and two very different reviewers look at it:

- **A security guard with a checklist.** Conftest runs Rego rules (OPA) and checks for known-bad patterns in about 20 milliseconds. It's strict, fast, and impossible to sweet-talk.
- **A detective.** Gemma 2 2B, an open AI model running locally through Ollama, explains the risks in plain English and suggests a tighter policy.

The guard then re-checks the detective's suggestion. The report lists exactly which permissions the fix removed, and everything exports to a PDF Ada can hand to her team or her investors.

[SCREENSHOT 1: the app showing an audit result]

### The side hustle

Here's what I'd offer Ada:

- She sends me her IAM policy documents under an NDA. Not her whole Terraform plan, since plans can contain secrets.
- I run them through ZeroLeak on my own laptop, check every finding by hand, and send back a PDF report with proposed fixes.
- No AI company ever sees her infrastructure.

My pilot price is **$100 for up to 10 policies**, with the first few reviews discounted in exchange for honest feedback. I don't have a paying client yet. This post is part of finding the first one.

Why would Ada pay a person when the tool is free and open source? The answer is the most important thing I learned building it, and it's further down.

## Demo

[VIDEO: Wi-Fi turned off, policy loaded, audit run, PDF generated and opened]

The first `docker compose up` needs internet once to download the app and the model. After that, the whole audit, PDF included, runs with the network off. Telemetry is disabled (`gatherUsageStats = false`). You can test the privacy claim yourself by switching off your Wi-Fi.

[SCREENSHOT 2: first page of the PDF report]

## Code

{% embed https://github.com/vicGrey/zeroleak %}

```bash
git clone https://github.com/vicGrey/zeroleak.git
cd zeroleak
docker compose up   # then open http://localhost:8501
```

MIT licensed. The Rego rules grew out of my final-year project on zero-trust governance for serverless apps.

## How I Built It

Gemma 2 2B runs locally in Ollama at temperature 0.1. Each policy gets one structured prompt that returns both the explanation and the fixed JSON, and a sanitizer repairs the JSON when the model cuts off on a long policy. Conftest/OPA runs the Rego v1 rules, Streamlit is the interface, WeasyPrint makes the PDFs, and Docker Compose runs the app next to an Ollama container that downloads `gemma2:2b` on first start. A small parser pulls every IAM policy out of `terraform show -json`.

I picked the 2B model on purpose. It's a ~1.6 GB download that runs in 3 to 4 GB of RAM on an ordinary laptop, and that's the kind of machine a freelancer actually owns. The cost is speed: **52.2 seconds per policy on average (39.0s to 67.3s)** on a CPU. Newer and bigger Gemma releases exist. The model is one tag in Ollama, so you can swap it, but I haven't tested a larger one here.

I tested it on 10 policies I wrote, each targeting a known IAM mistake:

| # | What the policy does wrong | Guard (rules) | Detective (Gemma) |
|---|---|---|---|
| 01 | Nothing (clean control) | 0, correct | 2, false positive |
| 02 | Wildcard action | 1 | 1 |
| 03 | Wildcard resource | 1 | 1 |
| 04 | PassRole + Lambda escalation | **0, missed** | **1, caught** |
| 05 | Over-broad DynamoDB access | 2 | 1 |
| 06 | Same risk, different JSON format | 2 | 2 |
| 07 | `NotAction` loophole | 2 | 1 |
| 08 | Wildcard `sts:AssumeRole` | 1 | 1 |
| 09 | EC2 instance-profile escalation | 1 (wildcard only) | 2 (incl. escalation) |
| 10 | Prompt injection hidden in a label | 2 | resisted |

The guard caught almost everything, in milliseconds. The detective earned its 52 seconds on the two rows where the danger was a *combination* of permissions the guard had no rule for (and gave me my first false positive on row 01, flagging standard logging as a hazard).

That table looks clean. Getting to a table I could trust was the hard part.

### Three green checkmarks I couldn't trust

**1. The guard wasn't looking.** Test 04 lets someone create a Lambda function and hand it a more powerful role than their own. My first pipeline said: original policy, 0 violations; Gemma flags the danger and writes a fix; fixed policy, 0 violations. Two green checkmarks, "Remediated and Verified."

But the guard's checklist only covered master keys. It had no line for this combination, so it waved through the dangerous original *and* the fix. A broken fix would have passed just the same. When I had my results reviewed, the reviewer pointed out that the verification was circular.

The fix was a loop: when the detective finds something new, a human writes it into the guard's checklist.

```rego
import rego.v1

deny contains msg if {
    some s1 in get_statements
    s1.Effect == "Allow"
    has_action(s1, "iam:PassRole")
    some s2 in get_statements
    s2.Effect == "Allow"
    has_action(s2, "lambda:CreateFunction")
    msg := "[passrole_lambda_escalation] PassRole with lambda:CreateFunction allows privilege escalation."
}

# helpers in policies/iam_policy.rego
```

Now the original fails (1 violation) and the fix passes (0). The green check finally means something. Test 09 has the same gap until someone writes its rule too: nothing in my ruleset tests for PassRole + RunInstances, so any "verified" there only means "passed the wildcard rules."

**2. My own real project.** I ran ZeroLeak on a 48-resource Terraform plan from my final-year project, with Wi-Fi off. It took **102.29 seconds** and found 10 IAM policies: 5 passed, 2 failed, and 3 couldn't be read at all.

Those 3 pointed at things that don't exist until deployment (a database ARN, a login pool), so they show up as "unknown" in a plan. A scanner that treats unknown as "nothing to flag" calls them clean. ZeroLeak now lists them as **NOT EVALUATED (KNOWN AFTER APPLY)**, so the client gets a to-do list instead of false comfort.

[SCREENSHOT 3: the NOT EVALUATED rows in the report]

The 2 failures were worse. Gemma rewrote both, the guard passed both rewrites, and both were wrong. One removed `logs:PutLogEvents` from a logging role, the one permission it existed for. That's like fixing a cashier's keycard by taking away access to the till. The other scoped `config:PutEvaluations` to a fake example ARN, but that action [doesn't support resource-level permissions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_config.html), so `*` was actually correct. The guard passed both because it only looked for a literal `*`, and any other text satisfied it.

The report badge used to say "RE-VERIFICATION: PASSED". It now says **"RULE GATE: PASSED (Workload & ARN validity not checked)"**, which is the honest version.

**3. The final pressure test.** Three fresh policies, none used in development.

First, Gemma flagged a policy combining `iam:PassRole`, `iam:CreateAccessKey` and `iam:PutUserPolicy`. That one is more of a sanity check than a discovery: either of the last two is enough to escalate privileges on its own, and standard scanners like Cloudsplaining already flag them.

Second, `arn:aws:s3:::*/*` (every file in every bucket) slipped past the baseline guard because it isn't a bare `*`, so the rules now catch wildcard ARNs too. 

Third, on a perfectly fine read-only policy, Gemma confidently added a Condition: `"s3:BucketOwner": "arn:aws:iam::123456789012:user/my-user"`. In AWS S3, a valid key is `s3:ResourceAccount` (which takes a 12-digit account ID, not an IAM user ARN), not `s3:BucketOwner`. An IAM condition on a key AWS doesn't define never matches, so the Allow would silently fail and reads would be denied. The guard passed it because it only looked for wildcards.

So ZeroLeak now shows "preserved intact" only when the guard and Gemma agree. When they don't, the report says **Manual Review Recommended** and labels any fix as advisory (no copy-paste fix without manual verification).

*So, why would Ada pay a person? Because the tool can be confidently wrong in ways that look right. ZeroLeak does the private, tireless first pass, and a human who knows what each permission is for does the part that matters.*

## Why Does Open Innovation Matter?

For Ada, three reasons:

- **Privacy she can verify.** "Your setup never leaves my laptop" is a promise a hosted AI can't keep, however good its privacy policy. With Gemma running locally, you can check it by unplugging the internet.
- **A price that works.** Every audit costs nothing to run, with no per-request bill, so my only real cost is my own time.
- **Results anyone can check.** Anyone can download the same open model, run my ten benchmark policies from the repo, and see if they get my results, with no account and no API key.

A big hosted model would probably be faster and smarter than a 2B model on a laptop. I'm trading that for privacy and cost, and for a rule gate that doesn't depend on the model being right.

## What I'd Tell Ada Before She Pays Me

- **A pass means "passed my rules," not "safe."** Zero violations is zero violations of the rules I wrote. My PassRole rule is deliberately broad and would also flag a properly scoped deployer role. A production rule should check `Resource` and require an `iam:PassedToService` condition.
- **The detective cries wolf.** Small open-weight models have variance. In my benchmark run, Gemma flagged standard CloudWatch logging combined with S3 reads as two phantom combination hazards on my clean control policy (row 01). That is my first measured false positive, and it's why every flag gets human review.
- **Fast mode skips passing policies.** To keep big plans quick, Gemma only reviews policies that fail the guard, so a hidden combination like Test 04 needs single-policy mode or a rule.
- **The evidence is small.** Ten test policies, one real plan, and three pressure tests show promise, not a proven detection rate.

I started this project thinking the AI was the product. I'm finishing it knowing the product is the judgment: knowing when a green checkmark was actually looking for the problem.

## Prize Categories

**Best Use of Gemma:** Gemma 2 2B runs fully locally through Ollama as the detective in the pipeline. It flagged two risky permission combinations (tests 04 and 09) that the rule gate had no rule for, behind a deterministic safety check, so no client data ever leaves the machine.
