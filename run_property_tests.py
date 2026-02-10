#!/usr/bin/env python3
"""
Runner script for property-based tests with detailed statistics.
"""

from hypothesis import given, settings, Verbosity
import test_property_finding_completeness as test_module

# Configure hypothesis to show more details
settings.register_profile("detailed", max_examples=100, verbosity=Verbosity.verbose)
settings.load_profile("detailed")

if __name__ == "__main__":
    print("Running property-based tests with detailed output...")
    print("=" * 70)
    
    # Run each test function
    test_functions = [
        ("Finding data completeness (generated)", 
         test_module.test_property_finding_data_completeness),
        ("Finding data completeness (direct)", 
         test_module.test_property_finding_completeness_direct_construction),
        ("Empty file_path violation", 
         test_module.test_property_finding_empty_file_path_violation),
        ("Invalid line_number violation", 
         test_module.test_property_finding_invalid_line_number_violation),
        ("Invalid confidence violation", 
         test_module.test_property_finding_invalid_confidence_violation),
    ]
    
    for name, test_func in test_functions:
        print(f"\n{name}:")
        print("-" * 70)
        test_func()
        print(f"✅ {name} passed")
    
    print("\n" + "=" * 70)
    print("🎉 All property-based tests completed successfully!")
