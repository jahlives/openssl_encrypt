"""
Unified Test Runner and Reporting System for OpenSSL Encrypt Testing Framework.

Orchestrates all test suites, generates comprehensive reports, and provides
unified interface for running security tests.
"""

import json
import time
import logging
import os
from typing import List, Dict, Any, Optional, Union, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
import threading
import concurrent.futures

from .base_test import BaseSecurityTest, TestResult, TestResultLevel, TestConfig
from .fuzz_testing import FuzzTestSuite
from .side_channel_tests import SideChannelTestSuite
from .kat_tests import KATTestSuite
from .benchmark_suite import BenchmarkTestSuite
from .memory_tests import MemoryTestSuite


class TestSuiteType(Enum):
    """Available test suite types."""
    FUZZ = "fuzz"
    SIDE_CHANNEL = "side_channel"
    KAT = "kat"
    BENCHMARK = "benchmark"
    MEMORY = "memory"
    ALL = "all"


@dataclass
class TestExecutionPlan:
    """Represents a plan for test execution."""
    suite_types: List[TestSuiteType]
    parallel_execution: bool = False
    max_workers: int = 3
    config: Dict[str, Any] = field(default_factory=dict)
    output_formats: List[str] = field(default_factory=lambda: ["json", "html"])
    output_directory: Optional[str] = None


@dataclass
class TestSuiteResult:
    """Results from a complete test suite execution."""
    suite_name: str
    suite_type: TestSuiteType
    execution_time: float
    test_results: List[TestResult]
    summary: Dict[str, Any]
    success: bool
    error_message: Optional[str] = None


@dataclass
class TestRunReport:
    """Comprehensive test run report."""
    run_id: str
    start_time: datetime
    end_time: datetime
    total_duration: float
    suite_results: List[TestSuiteResult]
    overall_summary: Dict[str, Any]
    system_info: Dict[str, Any]
    configuration: Dict[str, Any]


class ReportGenerator:
    """Generates test reports in various formats."""
    
    @staticmethod
    def generate_json_report(report: TestRunReport, output_path: str) -> None:
        """Generate JSON format report."""
        
        # Convert dataclasses to dictionaries for JSON serialization
        report_dict = {
            "run_id": report.run_id,
            "start_time": report.start_time.isoformat(),
            "end_time": report.end_time.isoformat(),
            "total_duration": report.total_duration,
            "suite_results": [],
            "overall_summary": report.overall_summary,
            "system_info": report.system_info,
            "configuration": report.configuration
        }
        
        # Convert suite results
        for suite_result in report.suite_results:
            suite_dict = {
                "suite_name": suite_result.suite_name,
                "suite_type": suite_result.suite_type.value,
                "execution_time": suite_result.execution_time,
                "success": suite_result.success,
                "error_message": suite_result.error_message,
                "summary": suite_result.summary,
                "test_results": [result.to_dict() for result in suite_result.test_results]
            }
            report_dict["suite_results"].append(suite_dict)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)
    
    @staticmethod
    def generate_html_report(report: TestRunReport, output_path: str) -> None:
        """Generate HTML format report."""
        
        # Calculate summary statistics
        total_tests = sum(len(sr.test_results) for sr in report.suite_results)
        passed_tests = sum(
            sum(1 for tr in sr.test_results if tr.level == TestResultLevel.PASS)
            for sr in report.suite_results
        )
        failed_tests = sum(
            sum(1 for tr in sr.test_results if tr.level in [TestResultLevel.ERROR, TestResultLevel.CRITICAL])
            for sr in report.suite_results
        )
        warning_tests = sum(
            sum(1 for tr in sr.test_results if tr.level == TestResultLevel.WARNING)
            for sr in report.suite_results
        )
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenSSL Encrypt Security Test Report</title>
    <style>
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{ 
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            border-bottom: 3px solid #007acc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #007acc;
            margin: 0;
            font-size: 2.2em;
        }}
        .header .subtitle {{
            color: #666;
            margin-top: 5px;
            font-size: 1.1em;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .summary-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 6px;
            border-left: 4px solid #007acc;
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            color: #333;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .summary-card .value {{
            font-size: 1.8em;
            font-weight: bold;
            color: #007acc;
        }}
        .success-rate {{
            font-size: 2.5em;
            font-weight: bold;
            text-align: center;
            margin: 20px 0;
        }}
        .success-rate.high {{ color: #28a745; }}
        .success-rate.medium {{ color: #ffc107; }}
        .success-rate.low {{ color: #dc3545; }}
        .test-suite {{
            margin: 30px 0;
            border: 1px solid #ddd;
            border-radius: 6px;
            overflow: hidden;
        }}
        .suite-header {{
            background: #007acc;
            color: white;
            padding: 15px 20px;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .suite-content {{
            padding: 20px;
        }}
        .test-result {{
            margin: 10px 0;
            padding: 12px;
            border-radius: 4px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .test-result.pass {{ background: #d4edda; border-left: 4px solid #28a745; }}
        .test-result.warning {{ background: #fff3cd; border-left: 4px solid #ffc107; }}
        .test-result.error {{ background: #f8d7da; border-left: 4px solid #dc3545; }}
        .test-result.critical {{ background: #f8d7da; border-left: 4px solid #721c24; }}
        .test-result.info {{ background: #d1ecf1; border-left: 4px solid #17a2b8; }}
        .test-name {{ font-weight: bold; }}
        .test-message {{ color: #666; font-size: 0.9em; margin-top: 4px; }}
        .test-duration {{ color: #888; font-size: 0.8em; }}
        .system-info {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 6px;
            margin-top: 30px;
        }}
        .system-info h3 {{
            margin-top: 0;
            color: #333;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }}
        .info-item {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }}
        .info-label {{ font-weight: bold; }}
        .info-value {{ color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 OpenSSL Encrypt Security Test Report</h1>
            <div class="subtitle">
                Generated on {report.end_time.strftime('%Y-%m-%d %H:%M:%S')} | 
                Run ID: {report.run_id} | 
                Duration: {report.total_duration:.1f}s
            </div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Total Tests</h3>
                <div class="value">{total_tests}</div>
            </div>
            <div class="summary-card">
                <h3>Passed</h3>
                <div class="value" style="color: #28a745">{passed_tests}</div>
            </div>
            <div class="summary-card">
                <h3>Warnings</h3>
                <div class="value" style="color: #ffc107">{warning_tests}</div>
            </div>
            <div class="summary-card">
                <h3>Failed</h3>
                <div class="value" style="color: #dc3545">{failed_tests}</div>
            </div>
        </div>
        
        <div class="success-rate {'high' if success_rate >= 90 else 'medium' if success_rate >= 70 else 'low'}">
            {success_rate:.1f}% Success Rate
        </div>
        """
        
        # Add test suite sections
        for suite_result in report.suite_results:
            suite_status = "✅ PASSED" if suite_result.success else "❌ FAILED"
            html_content += f"""
        <div class="test-suite">
            <div class="suite-header">
                <span>{suite_result.suite_name}</span>
                <span>{suite_status} ({len(suite_result.test_results)} tests, {suite_result.execution_time:.2f}s)</span>
            </div>
            <div class="suite-content">
            """
            
            if suite_result.error_message:
                html_content += f"""
                <div class="test-result error">
                    <div>
                        <div class="test-name">Suite Execution Error</div>
                        <div class="test-message">{suite_result.error_message}</div>
                    </div>
                </div>
                """
            
            for test_result in suite_result.test_results:
                level_class = test_result.level.value.lower()
                duration_text = f"{test_result.duration:.3f}s" if test_result.duration > 0 else ""
                
                html_content += f"""
                <div class="test-result {level_class}">
                    <div>
                        <div class="test-name">{test_result.test_name}</div>
                        <div class="test-message">{test_result.message}</div>
                    </div>
                    <div class="test-duration">{duration_text}</div>
                </div>
                """
            
            html_content += """
            </div>
        </div>
            """
        
        # Add system information
        html_content += f"""
        <div class="system-info">
            <h3>System Information</h3>
            <div class="info-grid">
        """
        
        for key, value in report.system_info.items():
            html_content += f"""
                <div class="info-item">
                    <span class="info-label">{key.replace('_', ' ').title()}:</span>
                    <span class="info-value">{value}</span>
                </div>
            """
        
        html_content += """
            </div>
        </div>
    </div>
</body>
</html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    @staticmethod
    def generate_text_report(report: TestRunReport, output_path: str) -> None:
        """Generate plain text format report."""
        
        lines = [
            "=" * 80,
            "OpenSSL Encrypt Security Test Report",
            "=" * 80,
            "",
            f"Run ID: {report.run_id}",
            f"Generated: {report.end_time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Duration: {report.total_duration:.1f} seconds",
            "",
            "OVERALL SUMMARY",
            "-" * 40,
        ]
        
        # Add overall statistics
        total_tests = sum(len(sr.test_results) for sr in report.suite_results)
        passed_tests = sum(
            sum(1 for tr in sr.test_results if tr.level == TestResultLevel.PASS)
            for sr in report.suite_results
        )
        failed_tests = sum(
            sum(1 for tr in sr.test_results if tr.level in [TestResultLevel.ERROR, TestResultLevel.CRITICAL])
            for sr in report.suite_results
        )
        
        lines.extend([
            f"Total Tests: {total_tests}",
            f"Passed: {passed_tests}",
            f"Failed: {failed_tests}",
            f"Success Rate: {(passed_tests/total_tests*100) if total_tests > 0 else 0:.1f}%",
            "",
            "TEST SUITE RESULTS",
            "-" * 40,
        ])
        
        # Add suite results
        for suite_result in report.suite_results:
            lines.extend([
                f"{suite_result.suite_name} ({suite_result.execution_time:.2f}s)",
                f"  Status: {'PASSED' if suite_result.success else 'FAILED'}",
                f"  Tests: {len(suite_result.test_results)}",
            ])
            
            if suite_result.error_message:
                lines.append(f"  Error: {suite_result.error_message}")
            
            lines.append("")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))


class SecurityTestRunner:
    """Main test runner orchestrating all security test suites."""
    
    def __init__(self):
        self.logger = logging.getLogger("SecurityTestRunner")
        self.available_suites = {
            TestSuiteType.FUZZ: FuzzTestSuite,
            TestSuiteType.SIDE_CHANNEL: SideChannelTestSuite,
            TestSuiteType.KAT: KATTestSuite,
            TestSuiteType.BENCHMARK: BenchmarkTestSuite,
            TestSuiteType.MEMORY: MemoryTestSuite,
        }
    
    def run_tests(self, execution_plan: TestExecutionPlan) -> TestRunReport:
        """Execute tests according to the execution plan."""
        
        start_time = datetime.now()
        run_id = f"test_run_{start_time.strftime('%Y%m%d_%H%M%S')}"
        
        self.logger.info(f"Starting test run {run_id}")
        
        # Determine which suites to run
        suites_to_run = []
        for suite_type in execution_plan.suite_types:
            if suite_type == TestSuiteType.ALL:
                suites_to_run.extend([
                    TestSuiteType.FUZZ,
                    TestSuiteType.SIDE_CHANNEL,
                    TestSuiteType.KAT,
                    TestSuiteType.BENCHMARK,
                    TestSuiteType.MEMORY
                ])
            else:
                suites_to_run.append(suite_type)
        
        # Remove duplicates while preserving order
        suites_to_run = list(dict.fromkeys(suites_to_run))
        
        # Execute test suites
        suite_results = []
        
        if execution_plan.parallel_execution and len(suites_to_run) > 1:
            suite_results = self._run_suites_parallel(suites_to_run, execution_plan)
        else:
            suite_results = self._run_suites_sequential(suites_to_run, execution_plan)
        
        end_time = datetime.now()
        total_duration = (end_time - start_time).total_seconds()
        
        # Generate overall summary
        overall_summary = self._generate_overall_summary(suite_results)
        
        # Collect system information
        system_info = self._collect_system_info()
        
        # Create test run report
        report = TestRunReport(
            run_id=run_id,
            start_time=start_time,
            end_time=end_time,
            total_duration=total_duration,
            suite_results=suite_results,
            overall_summary=overall_summary,
            system_info=system_info,
            configuration=execution_plan.config
        )
        
        # Generate reports
        self._generate_reports(report, execution_plan)
        
        self.logger.info(f"Test run {run_id} completed in {total_duration:.1f}s")
        
        return report
    
    def _run_suites_sequential(self, suite_types: List[TestSuiteType], 
                              execution_plan: TestExecutionPlan) -> List[TestSuiteResult]:
        """Run test suites sequentially."""
        
        results = []
        
        for suite_type in suite_types:
            result = self._run_single_suite(suite_type, execution_plan.config)
            results.append(result)
            
            # Log progress
            status = "PASSED" if result.success else "FAILED"
            self.logger.info(f"Suite {result.suite_name} {status} ({result.execution_time:.2f}s)")
        
        return results
    
    def _run_suites_parallel(self, suite_types: List[TestSuiteType],
                           execution_plan: TestExecutionPlan) -> List[TestSuiteResult]:
        """Run test suites in parallel."""
        
        results = []
        max_workers = min(execution_plan.max_workers, len(suite_types))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all suite executions
            future_to_suite = {
                executor.submit(self._run_single_suite, suite_type, execution_plan.config): suite_type
                for suite_type in suite_types
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_suite):
                suite_type = future_to_suite[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    status = "PASSED" if result.success else "FAILED"
                    self.logger.info(f"Suite {result.suite_name} {status} ({result.execution_time:.2f}s)")
                    
                except Exception as e:
                    self.logger.error(f"Suite {suite_type.value} failed with exception: {e}")
                    # Create error result
                    error_result = TestSuiteResult(
                        suite_name=suite_type.value,
                        suite_type=suite_type,
                        execution_time=0.0,
                        test_results=[],
                        summary={"error": str(e)},
                        success=False,
                        error_message=str(e)
                    )
                    results.append(error_result)
        
        # Sort results to match original suite order
        suite_order = {suite_type: i for i, suite_type in enumerate(suite_types)}
        results.sort(key=lambda r: suite_order.get(r.suite_type, 999))
        
        return results
    
    def _run_single_suite(self, suite_type: TestSuiteType, config: Dict[str, Any]) -> TestSuiteResult:
        """Run a single test suite."""
        
        if suite_type not in self.available_suites:
            return TestSuiteResult(
                suite_name=suite_type.value,
                suite_type=suite_type,
                execution_time=0.0,
                test_results=[],
                summary={},
                success=False,
                error_message=f"Suite type {suite_type.value} not available"
            )
        
        suite_class = self.available_suites[suite_type]
        suite_instance = suite_class()
        
        start_time = time.time()
        
        try:
            # Run the test suite
            test_results = suite_instance.run_tests(**config)
            execution_time = time.time() - start_time
            
            # Get suite summary
            summary = suite_instance.get_summary()
            
            success = all(
                result.level != TestResultLevel.CRITICAL 
                for result in test_results
            )
            
            return TestSuiteResult(
                suite_name=suite_instance.name,
                suite_type=suite_type,
                execution_time=execution_time,
                test_results=test_results,
                summary=summary,
                success=success
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Error running suite {suite_type.value}: {e}")
            
            return TestSuiteResult(
                suite_name=suite_type.value,
                suite_type=suite_type,
                execution_time=execution_time,
                test_results=[],
                summary={},
                success=False,
                error_message=str(e)
            )
    
    def _generate_overall_summary(self, suite_results: List[TestSuiteResult]) -> Dict[str, Any]:
        """Generate overall test run summary statistics."""
        
        total_suites = len(suite_results)
        successful_suites = sum(1 for sr in suite_results if sr.success)
        
        total_tests = sum(len(sr.test_results) for sr in suite_results)
        passed_tests = sum(
            sum(1 for tr in sr.test_results if tr.level == TestResultLevel.PASS)
            for sr in suite_results
        )
        warning_tests = sum(
            sum(1 for tr in sr.test_results if tr.level == TestResultLevel.WARNING)
            for sr in suite_results
        )
        error_tests = sum(
            sum(1 for tr in sr.test_results if tr.level in [TestResultLevel.ERROR, TestResultLevel.CRITICAL])
            for sr in suite_results
        )
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        return {
            "total_suites": total_suites,
            "successful_suites": successful_suites,
            "suite_success_rate": (successful_suites / total_suites * 100) if total_suites > 0 else 0,
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "warning_tests": warning_tests,
            "error_tests": error_tests,
            "test_success_rate": success_rate
        }
    
    def _collect_system_info(self) -> Dict[str, Any]:
        """Collect system information for the report."""
        
        import platform
        
        system_info = {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor() or "Unknown",
            "hostname": platform.node(),
        }
        
        # Try to get additional system info
        try:
            import psutil
            memory = psutil.virtual_memory()
            system_info.update({
                "total_memory_gb": round(memory.total / (1024**3), 2),
                "available_memory_gb": round(memory.available / (1024**3), 2),
                "cpu_count": psutil.cpu_count(),
                "cpu_count_logical": psutil.cpu_count(logical=True)
            })
        except ImportError:
            pass
        
        return system_info
    
    def _generate_reports(self, report: TestRunReport, execution_plan: TestExecutionPlan) -> None:
        """Generate test reports in requested formats."""
        
        output_dir = execution_plan.output_directory or "test_reports"
        os.makedirs(output_dir, exist_ok=True)
        
        base_filename = f"security_test_report_{report.run_id}"
        
        for output_format in execution_plan.output_formats:
            try:
                if output_format == "json":
                    output_path = os.path.join(output_dir, f"{base_filename}.json")
                    ReportGenerator.generate_json_report(report, output_path)
                    self.logger.info(f"JSON report generated: {output_path}")
                    
                elif output_format == "html":
                    output_path = os.path.join(output_dir, f"{base_filename}.html")
                    ReportGenerator.generate_html_report(report, output_path)
                    self.logger.info(f"HTML report generated: {output_path}")
                    
                elif output_format == "text":
                    output_path = os.path.join(output_dir, f"{base_filename}.txt")
                    ReportGenerator.generate_text_report(report, output_path)
                    self.logger.info(f"Text report generated: {output_path}")
                    
                else:
                    self.logger.warning(f"Unknown output format: {output_format}")
                    
            except Exception as e:
                self.logger.error(f"Failed to generate {output_format} report: {e}")
    
    def list_available_suites(self) -> List[str]:
        """List all available test suite types."""
        return [suite_type.value for suite_type in self.available_suites.keys()]
    
    def get_suite_info(self, suite_type: TestSuiteType) -> Dict[str, Any]:
        """Get information about a specific test suite."""
        
        if suite_type not in self.available_suites:
            return {"error": f"Suite type {suite_type.value} not available"}
        
        suite_class = self.available_suites[suite_type]
        suite_instance = suite_class()
        
        return {
            "name": suite_instance.name,
            "description": suite_instance.description,
            "type": suite_type.value
        }