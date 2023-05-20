# CICDGuard

[Overview](#overview) \| [How it works](#how-it-works) \| [Quickstart](#quickstart) \| [Roadmap](#roadmap) \| [Contact Me](#contribution--contact-me)

# Overview
CICD platforms are an integral part of the overall software supply chain and it processes a lot of sensitive data, compromise of which can affect the entire organization. Security IN CICD is a well discussed topic, security OF CICD deserves the same attention.

One of the challenges with security OF CICD, like most areas of security, is the lack of visibility of what actually makes a CICD ecosystem. Security starts with being aware of what needs to be secure.


CICDGuard is a graph based CICD ecosystem visualizer and security analyzer, which:
1) Represents entire CICD ecosystem in graph form, providing intuitive visibility and solving the awareness problem
2) Identifies common security flaws across supported technologies and provides industry best practices and guidelines for identified flaws
3) Technologies supported - GitHub, GitHub Action, Jenkins, JFrog, Spinnaker, Drone


# How it Works
![CICDGuard_Architecture](https://github.com/varchashva/CICDGuard/assets/33921557/88109649-d636-4a80-9ca3-d086d15664d0)

# Quickstart
1. Install Neo4j database and run it with default settings
2. Go to /scripts directory
3. Run the scanner as per your environment. Provide the environment variables, as applicable

# Roadmap
- Expansion of target technologies:
  - Spinnaker 
  - Drone
  - Harness
  - GitLab and so on…
- Expansion of analysis engine, includes parsing of different components to determine relationship across technologies:
  - Correlation between different repositories 
  - Build relating to repositories
  - Repositories and builds contributing to a particular micro-service
- More intuitive visualization 

# Contribution & Contact Me 

Thanks to [Jyoti Raval](https://www.linkedin.com/in/jyoti-raval-61565157) for being an exceptional QA.

Please reach out to me for any query/comment/suggestion: [![LinkedIn](https://img.shields.io/badge/linkedin-%230077B5.svg?&style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/pramod-rana-696ba062/) \| [![Twitter Follow](https://img.shields.io/twitter/follow/IAmVarchashva?style=social)](https://twitter.com/IAmVarchashva) \| [Raise an issue](https://github.com/varchashva/vPrioritizer/issues/new)
