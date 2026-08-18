from threat_intel_agent.services import services


def main() -> None:
    count = services.repository.seed()
    print(f"Seeded {count} synthetic threat-intelligence records")


if __name__ == "__main__":
    main()
