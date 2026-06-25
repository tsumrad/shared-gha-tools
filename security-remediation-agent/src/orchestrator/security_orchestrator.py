class SecurityOrchestrator:

    def __init__(
        self,
        vulnerabilityCollector,
        vulnerabilityNormalizer,
        triage,
        remediation,
        reviewer,
        reporter,
    ):
        self.vulnerabilityCollector = vulnerabilityCollector
        self.vulnerabilityNormalizer = vulnerabilityNormalizer
        self.triage = triage
        self.remediation = remediation
        self.reviewer = reviewer
        self.reporter = reporter


    async def run(self, repo):

        collected_vulnerabilities = await self.vulnerabilityCollector.collect(repo)
        vulnerabilities = await self.vulnerabilityNormalizer.normalize(collected_vulnerabilities)

        if not vulnerabilities:
            return "No vulnerabilities found"
    