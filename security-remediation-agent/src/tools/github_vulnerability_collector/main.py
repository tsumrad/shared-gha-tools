import asyncio

from ...orchestrator.security_orchestrator import SecurityOrchestrator

from ...agents import vulnerabilityCollectorAgent

async def main():

    collector = vulnerabilityCollectorAgent()

    orchestrator = SecurityOrchestrator(
        collector=collector,
    )


    result = await orchestrator.run(
        repo={
            "owner": "my-org",
            "name": "my-service",
        }
    )

    print(result)


if __name__ == "__main__":
    asyncio.run(main())