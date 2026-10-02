# IDEA — LeakHunter v2 (short version; full review PDF was shared in the group)

**Pitch:** "Your data is 'anonymized.' We just re-identified real people with free public data. Watch one AI find every leak, another fix it, and a referee prove the fixes hold. Now you try to break it."

**Problem:** most leaks come from unchecked permissions, not hacks; "anonymized" data often isn't (Sweeney: ~87% of Americans identifiable by ZIP + birth date + sex); AI chatbots on warehouses add a new leak path; audits happen once a year.

**What makes it different**
1. Re-identification attack using Snowflake's free public population data (also our Snowflake-track dataset requirement).
2. Proves fixes don't break the business: legit analyst queries are re-run alongside attacks.
3. A judge can open a hole live and watch it get caught and closed.
4. Attacks the AI layer too (stretch): plain-English questions to a data chatbot.
5. Open skill + open attack library; attacker model runs locally.
6. **Bouncer**, a second skill: blocks packages an AI agent invents or that look like typos, before they get installed and steal the warehouse key.

**vs. existing tools:** classification tools find where sensitive data is; LeakHunter proves whether it's reachable, fixes it, and proves the fix works without breaking legitimate work.

**Tracks:** Best Use of Snowflake (CoCo + free dataset + open-weight model) · Best Open-Source AI Project (Agent Skill + open-weight attacker + MIT repo).
