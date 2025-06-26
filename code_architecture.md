graph TD
    A[Start NetSim] --> B[Entry Point]
    B --> C1[CLI - main file]
    B --> C2[YAML Timeline - controller.py]

    %% CLI path
    C1 --> D1[main]
    D1 --> E1[Controller.cmdloop]
    E1 --> F1[Controller.do_start]
    F1 --> G1[PatternLaunchSpec.start]
    G1 --> H1[runner_entrypoint]
    H1 --> I1[pattern.generate]

    %% YAML path
    C2 --> D2[start_timeline]
    D2 --> E2[Orchestrator.launch_all]
    E2 --> F2[PatternLaunchSpec]
    F2 --> G2[PatternLaunchSpec.start]
    G2 --> H2[runner_entrypoint]
    H2 --> I2[pattern.generate]

    %% Shared
    I1 --> J[Shared Queue]
    I2 --> J
    J --> K[PacketSenderPool]
    K --> L[Scapy or PCAP Output]

    %% Optional loop
    D2 --> M[timeline_loop]