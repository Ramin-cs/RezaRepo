#!/usr/bin/env python3
"""
Central Phase Manager - Single Source of Truth
All phases are managed from here
"""

import sys
import os
from datetime import datetime
from typing import Dict, Any

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import all phase modules
try:
    from phases.phase1_real_ip_extraction import Phase1RealIPExtraction
    from phases.phase2_subdomain_discovery import Phase2SubdomainDiscovery
    from phases.phase3_port_scanning import Phase3PortScanning
    from phases.phase4_technology_detection import Phase4TechnologyDetection
    from phases.phase5_directory_discovery import Phase5DirectoryDiscovery
    from phases.phase6_parameter_discovery import Phase6ParameterDiscovery
    from phases.phase7_endpoint_discovery import Phase7EndpointDiscovery
    from phases.phase8_cloud_analysis import Phase8CloudAnalysis
    from phases.phase9_osint_analysis import Phase9OSINTAnalysis
    from phases.phase10_vulnerability_assessment import Phase10VulnerabilityAssessment
    
    PHASES_AVAILABLE = True
    print("✅ All phase modules loaded successfully")
    
except ImportError as e:
    print(f"❌ Error importing phase modules: {e}")
    PHASES_AVAILABLE = False

class PhaseManager:
    """Central Phase Manager - Single Source of Truth"""
    
    def __init__(self):
        self.phases = {}
        self._initialize_phases()
    
    def _initialize_phases(self):
        """Initialize all phase instances"""
        if not PHASES_AVAILABLE:
            print("⚠️ Phase modules not available")
            return
        
        try:
            self.phases = {
                1: Phase1RealIPExtraction(),
                2: Phase2SubdomainDiscovery(),
                3: Phase3PortScanning(),
                4: Phase4TechnologyDetection(),
                5: Phase5DirectoryDiscovery(),
                6: Phase6ParameterDiscovery(),
                7: Phase7EndpointDiscovery(),
                8: Phase8CloudAnalysis(),
                9: Phase9OSINTAnalysis(),
                10: Phase10VulnerabilityAssessment()
            }
            print(f"✅ Initialized {len(self.phases)} phase modules")
        except Exception as e:
            print(f"❌ Error initializing phases: {e}")
            self.phases = {}
    
    def run_phase(self, phase_number: int, target: str) -> Dict[str, Any]:
        """Run specific phase"""
        if not PHASES_AVAILABLE:
            return {
                'phase': phase_number,
                'target': target,
                'status': 'error',
                'error': 'Phase modules not available'
            }
        
        if phase_number not in self.phases:
            return {
                'phase': phase_number,
                'target': target,
                'status': 'error',
                'error': f'Phase {phase_number} not found'
            }
        
        try:
            print(f"🚀 Running Phase {phase_number} via PhaseManager")
            phase_instance = self.phases[phase_number]
            result = phase_instance.run_phase(target)
            print(f"✅ Phase {phase_number} completed via PhaseManager")
            return result
        except Exception as e:
            print(f"❌ Error running Phase {phase_number}: {e}")
            return {
                'phase': phase_number,
                'target': target,
                'status': 'error',
                'error': str(e)
            }
    
    def get_available_phases(self) -> list:
        """Get list of available phases"""
        return list(self.phases.keys())
    
    def is_phase_available(self, phase_number: int) -> bool:
        """Check if phase is available"""
        return phase_number in self.phases

# Global phase manager instance
phase_manager = PhaseManager()

def run_phase(phase_number: int, target: str) -> Dict[str, Any]:
    """Global function to run phases"""
    return phase_manager.run_phase(phase_number, target)

if __name__ == "__main__":
    # Test all phases
    test_target = "example.com"
    print(f"🧪 Testing all phases with target: {test_target}")
    
    for phase_num in range(1, 11):
        if phase_manager.is_phase_available(phase_num):
            print(f"\n--- Testing Phase {phase_num} ---")
            result = phase_manager.run_phase(phase_num, test_target)
            print(f"Status: {result.get('status', 'unknown')}")
        else:
            print(f"\n--- Phase {phase_num} not available ---")