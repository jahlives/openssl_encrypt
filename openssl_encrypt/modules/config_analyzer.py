#!/usr/bin/env python3
"""
Configuration Analysis Tool for OpenSSL Encrypt

This module provides comprehensive analysis of encryption configurations,
offering detailed insights into security posture, performance characteristics,
and compatibility considerations. It helps users understand their configuration
choices and provides actionable recommendations for improvement.

Design Philosophy:
- Comprehensive analysis across all security dimensions
- Clear, actionable recommendations without revealing vulnerabilities
- Performance impact assessment for informed decision-making
- Compatibility analysis for different use cases
- Future-proofing considerations for long-term security
"""

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from .security_scorer import SecurityScorer, SecurityLevel


class AnalysisCategory(Enum):
    """Categories for configuration analysis."""
    SECURITY = "security"
    PERFORMANCE = "performance"
    COMPATIBILITY = "compatibility"
    COMPLIANCE = "compliance"
    FUTURE_PROOFING = "future_proofing"


class RecommendationPriority(Enum):
    """Priority levels for recommendations."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AnalysisRecommendation:
    """Represents a configuration recommendation."""
    category: AnalysisCategory
    priority: RecommendationPriority
    title: str
    description: str
    action: str
    impact: str
    rationale: str
    applies_to: List[str] = field(default_factory=list)  # Use cases this applies to


@dataclass
class ConfigurationAnalysis:
    """Complete configuration analysis results."""
    overall_score: float
    security_level: SecurityLevel
    recommendations: List[AnalysisRecommendation]
    performance_assessment: Dict[str, Any]
    compatibility_matrix: Dict[str, Any]
    compliance_status: Dict[str, Any]
    future_proofing: Dict[str, Any]
    configuration_summary: Dict[str, Any]
    analysis_timestamp: str


class ConfigurationAnalyzer:
    """
    Advanced configuration analysis engine.
    
    Provides detailed analysis of encryption configurations across multiple
    dimensions including security, performance, compatibility, and compliance.
    """
    
    # Performance characteristics for different algorithms
    ALGORITHM_PERFORMANCE = {
        'fernet': {'speed': 'high', 'memory': 'low', 'cpu_intensive': False},
        'aes-gcm': {'speed': 'very_high', 'memory': 'low', 'cpu_intensive': False},
        'aes-gcm-siv': {'speed': 'high', 'memory': 'low', 'cpu_intensive': False},
        'aes-siv': {'speed': 'high', 'memory': 'low', 'cpu_intensive': False},
        'aes-ocb3': {'speed': 'high', 'memory': 'low', 'cpu_intensive': False},
        'chacha20-poly1305': {'speed': 'high', 'memory': 'low', 'cpu_intensive': False},
        'xchacha20-poly1305': {'speed': 'high', 'memory': 'low', 'cpu_intensive': False}
    }
    
    # KDF performance characteristics
    KDF_PERFORMANCE = {
        'pbkdf2': {'speed': 'high', 'memory': 'low', 'parallelizable': False},
        'scrypt': {'speed': 'medium', 'memory': 'medium', 'parallelizable': False},
        'argon2': {'speed': 'medium', 'memory': 'high', 'parallelizable': True},
        'balloon': {'speed': 'medium', 'memory': 'medium', 'parallelizable': True},
        'hkdf': {'speed': 'very_high', 'memory': 'low', 'parallelizable': False}
    }
    
    # Compliance frameworks compatibility
    COMPLIANCE_FRAMEWORKS = {
        'fips_140_2': {
            'approved_algorithms': ['aes-gcm', 'aes-gcm-siv'],
            'approved_kdfs': ['pbkdf2'],
            'approved_hashes': ['sha256', 'sha512', 'sha384']
        },
        'common_criteria': {
            'approved_algorithms': ['aes-gcm', 'aes-gcm-siv', 'aes-siv'],
            'approved_kdfs': ['pbkdf2', 'scrypt'],
            'approved_hashes': ['sha256', 'sha512', 'sha384', 'sha3_256', 'sha3_512']
        },
        'nist_guidelines': {
            'approved_algorithms': ['aes-gcm', 'chacha20-poly1305', 'xchacha20-poly1305'],
            'approved_kdfs': ['pbkdf2', 'argon2'],
            'approved_hashes': ['sha256', 'sha512', 'sha3_256', 'sha3_512', 'blake3']
        }
    }
    
    # Use case specific requirements
    USE_CASE_REQUIREMENTS = {
        'personal': {
            'min_security_level': SecurityLevel.MODERATE,
            'performance_priority': 'high',
            'complexity_tolerance': 'low'
        },
        'business': {
            'min_security_level': SecurityLevel.GOOD,
            'performance_priority': 'medium',
            'complexity_tolerance': 'medium'
        },
        'compliance': {
            'min_security_level': SecurityLevel.HIGH,
            'performance_priority': 'low',
            'complexity_tolerance': 'high'
        },
        'archival': {
            'min_security_level': SecurityLevel.VERY_HIGH,
            'performance_priority': 'low',
            'complexity_tolerance': 'high'
        }
    }
    
    def __init__(self):
        """Initialize the configuration analyzer."""
        self.scorer = SecurityScorer()
    
    def analyze_configuration(
        self,
        config: Dict[str, Any],
        use_case: Optional[str] = None,
        compliance_requirements: Optional[List[str]] = None
    ) -> ConfigurationAnalysis:
        """
        Perform comprehensive analysis of a configuration.
        
        Args:
            config: Complete configuration dictionary
            use_case: Target use case for context-aware analysis
            compliance_requirements: Required compliance frameworks
            
        Returns:
            Complete configuration analysis
        """
        # Extract configuration components
        hash_config = self._extract_hash_config(config)
        kdf_config = self._extract_kdf_config(config)
        cipher_info = self._extract_cipher_info(config)
        pqc_info = self._extract_pqc_info(config)
        
        # Get security scores
        security_analysis = self.scorer.score_configuration(
            hash_config, kdf_config, cipher_info, pqc_info
        )
        
        # Perform detailed analysis
        recommendations = self._generate_recommendations(
            config, security_analysis, use_case, compliance_requirements
        )
        
        performance_assessment = self._assess_performance(config)
        compatibility_matrix = self._analyze_compatibility(config)
        compliance_status = self._check_compliance(config, compliance_requirements or [])
        future_proofing = self._assess_future_proofing(config)
        configuration_summary = self._generate_summary(config, security_analysis)
        
        return ConfigurationAnalysis(
            overall_score=security_analysis['overall']['score'],
            security_level=security_analysis['overall']['level'],
            recommendations=recommendations,
            performance_assessment=performance_assessment,
            compatibility_matrix=compatibility_matrix,
            compliance_status=compliance_status,
            future_proofing=future_proofing,
            configuration_summary=configuration_summary,
            analysis_timestamp=time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        )
    
    def _extract_hash_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Extract hash configuration from full config."""
        hash_config = {}
        
        # Extract hash algorithms and their rounds
        hash_algorithms = [
            'sha256', 'sha512', 'sha384', 'sha224',
            'sha3_256', 'sha3_512', 'sha3_384', 'sha3_224',
            'blake2b', 'blake3', 'shake256', 'shake128', 'whirlpool'
        ]
        
        for algo in hash_algorithms:
            rounds_key = f'{algo}_rounds'
            if rounds_key in config and config[rounds_key] and config[rounds_key] > 0:
                hash_config[algo] = {'rounds': config[rounds_key]}
        
        return hash_config
    
    def _extract_kdf_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Extract KDF configuration from full config."""
        kdf_config = {}
        
        # PBKDF2
        pbkdf2_iterations = config.get('pbkdf2_iterations', 0) or 0
        if pbkdf2_iterations > 0:
            kdf_config['pbkdf2'] = {
                'enabled': True,
                'rounds': pbkdf2_iterations
            }
        
        # Argon2
        if config.get('enable_argon2', False):
            kdf_config['argon2'] = {
                'enabled': True,
                'memory_cost': config.get('argon2_memory', 65536),
                'time_cost': config.get('argon2_time', 3),
                'parallelism': config.get('argon2_parallelism', 1)
            }
        
        # Scrypt
        if config.get('enable_scrypt', False):
            kdf_config['scrypt'] = {
                'enabled': True,
                'n': config.get('scrypt_n', 16384),
                'r': config.get('scrypt_r', 8),
                'p': config.get('scrypt_p', 1)
            }
        
        # Balloon hashing
        if config.get('enable_balloon', False):
            kdf_config['balloon'] = {
                'enabled': True,
                'time_cost': config.get('balloon_time_cost', 1),
                'space_cost': config.get('balloon_space_cost', 1024)
            }
        
        # HKDF
        if config.get('enable_hkdf', False):
            kdf_config['hkdf'] = {
                'enabled': True,
                'rounds': config.get('hkdf_rounds', 1)
            }
        
        return kdf_config
    
    def _extract_cipher_info(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Extract cipher information from full config."""
        return {
            'algorithm': config.get('algorithm', 'aes-gcm'),
            'key_size': 256  # Standard for all supported algorithms
        }
    
    def _extract_pqc_info(self, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract post-quantum configuration from full config."""
        pqc_algorithm = config.get('pqc_algorithm')
        if not pqc_algorithm:
            return None
        
        return {
            'enabled': True,
            'algorithm': pqc_algorithm,
            'hybrid': 'hybrid' in pqc_algorithm.lower()
        }
    
    def _generate_recommendations(
        self,
        config: Dict[str, Any],
        security_analysis: Dict[str, Any],
        use_case: Optional[str],
        compliance_requirements: Optional[List[str]]
    ) -> List[AnalysisRecommendation]:
        """Generate comprehensive recommendations."""
        recommendations = []
        
        # Security-based recommendations
        recommendations.extend(self._security_recommendations(config, security_analysis))
        
        # Performance-based recommendations
        recommendations.extend(self._performance_recommendations(config))
        
        # Use case specific recommendations
        if use_case:
            recommendations.extend(self._use_case_recommendations(config, use_case, security_analysis))
        
        # Compliance recommendations
        if compliance_requirements:
            recommendations.extend(self._compliance_recommendations(config, compliance_requirements))
        
        # Future-proofing recommendations
        recommendations.extend(self._future_proofing_recommendations(config))
        
        # Sort by priority
        priority_order = {
            RecommendationPriority.CRITICAL: 0,
            RecommendationPriority.HIGH: 1,
            RecommendationPriority.MEDIUM: 2,
            RecommendationPriority.LOW: 3,
            RecommendationPriority.INFO: 4
        }
        
        return sorted(recommendations, key=lambda r: priority_order[r.priority])
    
    def _security_recommendations(
        self, 
        config: Dict[str, Any], 
        security_analysis: Dict[str, Any]
    ) -> List[AnalysisRecommendation]:
        """Generate security-focused recommendations."""
        recommendations = []
        overall_score = security_analysis['overall']['score']
        
        # Critical security issues
        if overall_score < 3.0:
            recommendations.append(AnalysisRecommendation(
                category=AnalysisCategory.SECURITY,
                priority=RecommendationPriority.CRITICAL,
                title="Security level below recommended minimum",
                description="Current configuration provides inadequate security for most use cases",
                action="Upgrade to --secure or --max-security configuration",
                impact="Significantly improved protection against attacks",
                rationale="Security score below 3.0 indicates basic vulnerabilities",
                applies_to=["all"]
            ))
        
        # Hash configuration recommendations
        if security_analysis['hash_analysis']['score'] < 4.0:
            recommendations.append(AnalysisRecommendation(
                category=AnalysisCategory.SECURITY,
                priority=RecommendationPriority.HIGH,
                title="Hash configuration could be strengthened",
                description="Current hash setup may not provide optimal security",
                action="Consider enabling additional hash functions or increasing rounds",
                impact="Enhanced password protection and key derivation security",
                rationale="Multiple hash functions provide defense in depth",
                applies_to=["business", "compliance", "archival"]
            ))
        
        # KDF recommendations
        if security_analysis['kdf_analysis']['score'] < 4.0:
            recommendations.append(AnalysisRecommendation(
                category=AnalysisCategory.SECURITY,
                priority=RecommendationPriority.HIGH,
                title="Key derivation could be enhanced",
                description="Current KDF configuration may be vulnerable to advanced attacks",
                action="Enable Argon2 or increase memory/time costs for existing KDFs",
                impact="Better protection against GPU and ASIC-based attacks",
                rationale="Memory-hard functions significantly increase attack costs",
                applies_to=["business", "compliance", "archival"]
            ))
        
        # Post-quantum recommendations
        if not security_analysis['pqc_analysis']['enabled']:
            priority = RecommendationPriority.MEDIUM
            if any(case in config.get('use_case', '') for case in ['archival', 'compliance']):
                priority = RecommendationPriority.HIGH
            
            recommendations.append(AnalysisRecommendation(
                category=AnalysisCategory.SECURITY,
                priority=priority,
                title="Consider post-quantum encryption",
                description="Current configuration lacks future protection against quantum computers",
                action="Add --quantum-safe pq-standard for basic protection",
                impact="Future-proof security against quantum computing threats",
                rationale="Quantum computers may break current cryptography within 10-20 years",
                applies_to=["archival", "compliance", "high-security"]
            ))
        
        return recommendations
    
    def _performance_recommendations(
        self,
        config: Dict[str, Any]
    ) -> List[AnalysisRecommendation]:
        """Generate performance-focused recommendations."""
        recommendations = []
        
        algorithm = config.get('algorithm', 'aes-gcm')
        
        # Algorithm performance suggestions
        if algorithm == 'fernet':
            recommendations.append(AnalysisRecommendation(
                category=AnalysisCategory.PERFORMANCE,
                priority=RecommendationPriority.INFO,
                title="Alternative algorithms available for better performance",
                description="Fernet is secure but not the fastest option available",
                action="Consider --crypto-family aes for better performance",
                impact="Improved encryption/decryption speed",
                rationale="AES-GCM benefits from hardware acceleration on most systems",
                applies_to=["personal", "business"]
            ))
        
        # Memory usage recommendations
        if config.get('enable_argon2') and config.get('argon2_memory', 0) > 2097152:  # 2GB
            recommendations.append(AnalysisRecommendation(
                category=AnalysisCategory.PERFORMANCE,
                priority=RecommendationPriority.MEDIUM,
                title="High memory usage may impact system performance",
                description="Argon2 memory cost is set very high",
                action="Consider reducing --argon2-memory for better system responsiveness",
                impact="Reduced memory pressure and faster key derivation",
                rationale="Balance security with system usability",
                applies_to=["personal"]
            ))
        
        # Multiple KDF warning
        active_kdfs = sum([
            config.get('enable_argon2', False),
            config.get('enable_scrypt', False),
            config.get('pbkdf2_iterations', 0) > 0,
            config.get('enable_balloon', False)
        ])
        
        if active_kdfs > 2:
            recommendations.append(AnalysisRecommendation(
                category=AnalysisCategory.PERFORMANCE,
                priority=RecommendationPriority.LOW,
                title="Multiple KDFs enabled may slow key derivation",
                description="Using many key derivation functions increases processing time",
                action="Consider using fewer, stronger KDFs for better performance",
                impact="Faster encryption start times",
                rationale="Argon2 alone with high parameters often provides better security/performance balance",
                applies_to=["personal", "business"]
            ))
        
        return recommendations
    
    def _use_case_recommendations(
        self,
        config: Dict[str, Any],
        use_case: str,
        security_analysis: Dict[str, Any]
    ) -> List[AnalysisRecommendation]:
        """Generate use case specific recommendations."""
        recommendations = []
        
        if use_case not in self.USE_CASE_REQUIREMENTS:
            return recommendations
        
        requirements = self.USE_CASE_REQUIREMENTS[use_case]
        current_level = security_analysis['overall']['level']
        
        # Check if security level meets use case requirements
        if current_level.value < requirements['min_security_level'].value:
            priority = RecommendationPriority.HIGH
            if use_case in ['compliance', 'archival']:
                priority = RecommendationPriority.CRITICAL
            
            recommendations.append(AnalysisRecommendation(
                category=AnalysisCategory.SECURITY,
                priority=priority,
                title=f"Security level insufficient for {use_case} use case",
                description=f"Current security level ({current_level.name}) below minimum for {use_case} ({requirements['min_security_level'].name})",
                action=f"Upgrade configuration using --for-{use_case} or stronger security settings",
                impact="Appropriate security level for intended use case",
                rationale=f"{use_case.title()} use case requires higher security guarantees",
                applies_to=[use_case]
            ))
        
        # Use case specific recommendations
        if use_case == 'archival':
            if not security_analysis['pqc_analysis']['enabled']:
                recommendations.append(AnalysisRecommendation(
                    category=AnalysisCategory.FUTURE_PROOFING,
                    priority=RecommendationPriority.HIGH,
                    title="Post-quantum encryption essential for archival storage",
                    description="Long-term data storage requires protection against future quantum computers",
                    action="Enable --quantum-safe pq-high for archival data",
                    impact="Ensures data remains secure for decades",
                    rationale="Archival data may be accessed long after quantum computers become viable",
                    applies_to=["archival"]
                ))
        
        elif use_case == 'compliance':
            # Check for compliance-friendly algorithms
            algorithm = config.get('algorithm', 'aes-gcm')
            if algorithm not in ['aes-gcm', 'aes-gcm-siv']:
                recommendations.append(AnalysisRecommendation(
                    category=AnalysisCategory.COMPLIANCE,
                    priority=RecommendationPriority.HIGH,
                    title="Algorithm may not meet compliance requirements",
                    description=f"Current algorithm ({algorithm}) may not be approved by all frameworks",
                    action="Consider using AES-GCM or AES-GCM-SIV for broader compliance",
                    impact="Better alignment with regulatory requirements",
                    rationale="FIPS 140-2 and Common Criteria have specific algorithm requirements",
                    applies_to=["compliance"]
                ))
        
        elif use_case == 'personal':
            # Suggest simplification if over-engineered
            if security_analysis['overall']['score'] > 8.0:
                recommendations.append(AnalysisRecommendation(
                    category=AnalysisCategory.PERFORMANCE,
                    priority=RecommendationPriority.INFO,
                    title="Configuration may be more complex than needed",
                    description="Current security level exceeds typical personal file protection requirements",
                    action="Consider --secure configuration for better performance",
                    impact="Faster operations while maintaining adequate security",
                    rationale="Personal files typically don't require maximum security settings",
                    applies_to=["personal"]
                ))
        
        return recommendations
    
    def _compliance_recommendations(
        self,
        config: Dict[str, Any],
        compliance_requirements: List[str]
    ) -> List[AnalysisRecommendation]:
        """Generate compliance-specific recommendations."""
        recommendations = []
        
        for framework in compliance_requirements:
            if framework not in self.COMPLIANCE_FRAMEWORKS:
                continue
            
            requirements = self.COMPLIANCE_FRAMEWORKS[framework]
            
            # Check algorithm compliance
            algorithm = config.get('algorithm', 'aes-gcm')
            approved_algorithms = requirements.get('approved_algorithms', []) or []
            if algorithm not in approved_algorithms:
                recommendations.append(AnalysisRecommendation(
                    category=AnalysisCategory.COMPLIANCE,
                    priority=RecommendationPriority.CRITICAL,
                    title=f"Algorithm not approved by {framework.replace('_', ' ').title()}",
                    description=f"Current algorithm ({algorithm}) not in approved list",
                    action=f"Use approved algorithm: {', '.join(approved_algorithms)}",
                    impact=f"Compliance with {framework.replace('_', ' ').title()} requirements",
                    rationale="Regulatory compliance requires use of approved cryptographic algorithms",
                    applies_to=["compliance"]
                ))
            
            # Check KDF compliance
            active_kdfs = []
            if config.get('pbkdf2_iterations', 0) > 0:
                active_kdfs.append('pbkdf2')
            if config.get('enable_scrypt', False):
                active_kdfs.append('scrypt')
            if config.get('enable_argon2', False):
                active_kdfs.append('argon2')
            
            approved_kdfs_list = requirements.get('approved_kdfs', []) or []
            non_compliant_kdfs = [kdf for kdf in active_kdfs if kdf not in approved_kdfs_list]
            if non_compliant_kdfs:
                recommendations.append(AnalysisRecommendation(
                    category=AnalysisCategory.COMPLIANCE,
                    priority=RecommendationPriority.HIGH,
                    title=f"Some KDFs not approved by {framework.replace('_', ' ').title()}",
                    description=f"KDFs not compliant: {', '.join(non_compliant_kdfs)}",
                    action=f"Use only approved KDFs: {', '.join(approved_kdfs_list)}",
                    impact=f"Full compliance with {framework.replace('_', ' ').title()}",
                    rationale="All cryptographic components must be from approved lists",
                    applies_to=["compliance"]
                ))
        
        return recommendations
    
    def _future_proofing_recommendations(
        self,
        config: Dict[str, Any]
    ) -> List[AnalysisRecommendation]:
        """Generate future-proofing recommendations."""
        recommendations = []
        
        # Algorithm longevity assessment
        algorithm = config.get('algorithm', 'aes-gcm')
        
        if algorithm in ['aes-ocb3']:
            recommendations.append(AnalysisRecommendation(
                category=AnalysisCategory.FUTURE_PROOFING,
                priority=RecommendationPriority.MEDIUM,
                title="Algorithm may face deprecation in future",
                description="AES-OCB3 has patent concerns and may be deprecated",
                action="Consider migrating to AES-GCM or ChaCha20-Poly1305",
                impact="Long-term algorithm support and compatibility",
                rationale="Patent-encumbered algorithms may face adoption issues",
                applies_to=["archival", "business"]
            ))
        
        # Key size considerations
        recommendations.append(AnalysisRecommendation(
            category=AnalysisCategory.FUTURE_PROOFING,
            priority=RecommendationPriority.INFO,
            title="Current key sizes adequate for foreseeable future",
            description="256-bit keys provide security well beyond current requirements",
            action="No action needed - current configuration is future-proof",
            impact="Continued security as computational power increases",
            rationale="256-bit symmetric keys remain secure against all known attacks",
            applies_to=["all"]
        ))
        
        return recommendations
    
    def _assess_performance(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Assess performance characteristics of the configuration."""
        algorithm = config.get('algorithm', 'aes-gcm')
        
        # Base performance from algorithm
        algo_perf = self.ALGORITHM_PERFORMANCE.get(algorithm, {
            'speed': 'medium', 'memory': 'medium', 'cpu_intensive': True
        })
        
        # KDF impact assessment
        kdf_impact = {'speed_penalty': 'low', 'memory_usage': 'low', 'cpu_usage': 'low'}
        
        if config.get('enable_argon2', False):
            memory_mb = config.get('argon2_memory', 65536) // 1024
            if memory_mb > 1024:  # > 1GB
                kdf_impact['memory_usage'] = 'high'
                kdf_impact['speed_penalty'] = 'high'
            elif memory_mb > 512:  # > 512MB
                kdf_impact['memory_usage'] = 'medium'
                kdf_impact['speed_penalty'] = 'medium'
        
        if config.get('enable_scrypt', False):
            kdf_impact['speed_penalty'] = 'medium'
            kdf_impact['memory_usage'] = 'medium'
        
        # Hash rounds impact
        total_hash_rounds = sum([
            config.get('sha256_rounds', 0),
            config.get('sha512_rounds', 0),
            config.get('blake2b_rounds', 0),
            config.get('blake3_rounds', 0),
            config.get('pbkdf2_iterations', 0)
        ])
        
        if total_hash_rounds > 500000:
            kdf_impact['speed_penalty'] = 'high'
        elif total_hash_rounds > 200000:
            kdf_impact['speed_penalty'] = 'medium'
        
        # Overall assessment
        performance_score = 5.0  # Base score
        
        if algo_perf['speed'] == 'very_high':
            performance_score += 1.5
        elif algo_perf['speed'] == 'high':
            performance_score += 1.0
        elif algo_perf['speed'] == 'medium':
            performance_score += 0.0
        else:  # low
            performance_score -= 1.0
        
        if kdf_impact['speed_penalty'] == 'high':
            performance_score -= 2.0
        elif kdf_impact['speed_penalty'] == 'medium':
            performance_score -= 1.0
        
        return {
            'overall_score': max(1.0, min(10.0, performance_score)),
            'algorithm_characteristics': algo_perf,
            'kdf_impact': kdf_impact,
            'estimated_relative_speed': self._calculate_speed_estimate(performance_score),
            'memory_requirements': self._calculate_memory_requirements(config),
            'cpu_intensity': self._calculate_cpu_intensity(config)
        }
    
    def _calculate_speed_estimate(self, score: float) -> str:
        """Convert performance score to speed estimate."""
        if score >= 8.0:
            return "very_fast"
        elif score >= 6.0:
            return "fast"
        elif score >= 4.0:
            return "moderate"
        elif score >= 2.0:
            return "slow"
        else:
            return "very_slow"
    
    def _calculate_memory_requirements(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate memory requirements."""
        base_memory = 50  # MB base requirement
        
        if config.get('enable_argon2', False):
            argon2_memory = config.get('argon2_memory', 65536) // 1024  # Convert to MB
            base_memory += argon2_memory
        
        if config.get('enable_scrypt', False):
            scrypt_n = config.get('scrypt_n', 16384)
            scrypt_r = config.get('scrypt_r', 8)
            scrypt_memory = (scrypt_n * scrypt_r * 128) // (1024 * 1024)  # Convert to MB
            base_memory += scrypt_memory
        
        return {
            'estimated_peak_mb': base_memory,
            'classification': 'high' if base_memory > 1024 else 'medium' if base_memory > 256 else 'low'
        }
    
    def _calculate_cpu_intensity(self, config: Dict[str, Any]) -> str:
        """Calculate CPU intensity classification."""
        intensity_score = 1.0
        
        # Hash rounds contribution
        total_rounds = sum([
            config.get('sha256_rounds', 0),
            config.get('sha512_rounds', 0),
            config.get('blake2b_rounds', 0),
            config.get('blake3_rounds', 0),
            config.get('pbkdf2_iterations', 0)
        ])
        
        if total_rounds > 500000:
            intensity_score += 2.0
        elif total_rounds > 200000:
            intensity_score += 1.0
        
        # KDF contribution
        if config.get('enable_argon2', False):
            time_cost = config.get('argon2_time', 3)
            intensity_score += time_cost * 0.5
        
        if config.get('enable_scrypt', False):
            intensity_score += 1.0
        
        if intensity_score >= 4.0:
            return "very_high"
        elif intensity_score >= 3.0:
            return "high"
        elif intensity_score >= 2.0:
            return "medium"
        else:
            return "low"
    
    def _analyze_compatibility(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze compatibility across different platforms and use cases."""
        algorithm = config.get('algorithm', 'aes-gcm')
        
        # Platform compatibility
        platform_compat = {
            'windows': True,
            'macos': True,
            'linux': True,
            'mobile': algorithm in ['aes-gcm', 'chacha20-poly1305'],  # Hardware acceleration
            'embedded': algorithm in ['aes-gcm', 'fernet']  # Simpler implementations
        }
        
        # Library compatibility
        library_compat = {
            'cryptography_py': True,  # All our algorithms supported
            'openssl': algorithm.startswith('aes') or 'chacha20' in algorithm,
            'bouncycastle': True,
            'web_crypto_api': algorithm in ['aes-gcm'],
            'nodejs_crypto': algorithm in ['aes-gcm', 'chacha20-poly1305']
        }
        
        # File format compatibility
        format_compat = {
            'current_version': True,
            'backward_compatible': True,
            'forward_compatible': True  # Our format is designed for forward compatibility
        }
        
        return {
            'platform_compatibility': platform_compat,
            'library_compatibility': library_compat,
            'format_compatibility': format_compat,
            'overall_compatibility_score': self._calculate_compatibility_score(
                platform_compat, library_compat, format_compat
            )
        }
    
    def _calculate_compatibility_score(
        self, 
        platform: Dict[str, bool], 
        library: Dict[str, bool], 
        format: Dict[str, bool]
    ) -> float:
        """Calculate overall compatibility score."""
        total_checks = len(platform) + len(library) + len(format)
        passed_checks = sum(platform.values()) + sum(library.values()) + sum(format.values())
        return (passed_checks / total_checks) * 10.0
    
    def _check_compliance(
        self, 
        config: Dict[str, Any], 
        requirements: List[str]
    ) -> Dict[str, Any]:
        """Check compliance with specified frameworks."""
        compliance_results = {}
        
        for framework in requirements:
            if framework not in self.COMPLIANCE_FRAMEWORKS:
                compliance_results[framework] = {
                    'supported': False,
                    'reason': 'Framework not recognized'
                }
                continue
            
            requirements_def = self.COMPLIANCE_FRAMEWORKS[framework]
            algorithm = config.get('algorithm', 'aes-gcm')
            
            # Check algorithm compliance
            approved_algorithms = requirements_def.get('approved_algorithms', []) or []
            algo_compliant = algorithm in approved_algorithms
            
            # Check KDF compliance
            active_kdfs = []
            if config.get('pbkdf2_iterations', 0) > 0:
                active_kdfs.append('pbkdf2')
            if config.get('enable_scrypt', False):
                active_kdfs.append('scrypt')
            if config.get('enable_argon2', False):
                active_kdfs.append('argon2')
            
            approved_kdfs = requirements_def.get('approved_kdfs', []) or []
            kdf_compliant = all(kdf in approved_kdfs for kdf in active_kdfs)
            
            overall_compliant = algo_compliant and kdf_compliant
            
            compliance_results[framework] = {
                'compliant': overall_compliant,
                'algorithm_compliant': algo_compliant,
                'kdf_compliant': kdf_compliant,
                'issues': []
            }
            
            if not algo_compliant:
                compliance_results[framework]['issues'].append(
                    f"Algorithm {algorithm} not approved"
                )
            
            if not kdf_compliant:
                non_compliant = [kdf for kdf in active_kdfs if kdf not in approved_kdfs]
                compliance_results[framework]['issues'].append(
                    f"KDFs not approved: {', '.join(non_compliant)}"
                )
        
        return compliance_results
    
    def _assess_future_proofing(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Assess future-proofing characteristics."""
        algorithm = config.get('algorithm', 'aes-gcm')
        
        # Algorithm longevity assessment
        longevity_score = 8.0  # Base score for modern algorithms
        
        if algorithm in ['fernet']:
            longevity_score = 7.0  # Good but not cutting edge
        elif algorithm in ['aes-ocb3']:
            longevity_score = 6.0  # Patent concerns
        elif algorithm in ['xchacha20-poly1305']:
            longevity_score = 9.0  # Very modern
        
        # Post-quantum readiness
        pqc_ready = config.get('pqc_algorithm') is not None
        if pqc_ready:
            longevity_score += 2.0
        
        # Key size adequacy
        key_size_score = 10.0  # 256-bit keys are future-proof
        
        return {
            'algorithm_longevity_score': min(10.0, longevity_score),
            'key_size_adequacy_score': key_size_score,
            'post_quantum_ready': pqc_ready,
            'estimated_secure_years': self._estimate_secure_years(longevity_score, pqc_ready),
            'future_proofing_recommendations': self._get_future_proofing_tips(config)
        }
    
    def _estimate_secure_years(self, longevity_score: float, pqc_ready: bool) -> str:
        """Estimate how many years the configuration will remain secure."""
        base_years = int(longevity_score * 3)  # Base estimation
        
        if pqc_ready:
            return f"{base_years}+ years (quantum-resistant)"
        else:
            quantum_risk_years = min(base_years, 15)  # Quantum risk within 15 years
            return f"{quantum_risk_years} years (until quantum threat)"
    
    def _get_future_proofing_tips(self, config: Dict[str, Any]) -> List[str]:
        """Get future-proofing tips."""
        tips = []
        
        if not config.get('pqc_algorithm'):
            tips.append("Consider enabling post-quantum encryption for long-term security")
        
        algorithm = config.get('algorithm', 'aes-gcm')
        if algorithm == 'aes-ocb3':
            tips.append("Consider migrating to patent-free algorithms like AES-GCM")
        
        tips.append("Regularly review and update security configurations")
        tips.append("Monitor cryptographic standards for new recommendations")
        
        return tips
    
    def _generate_summary(
        self, 
        config: Dict[str, Any], 
        security_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate configuration summary."""
        algorithm = config.get('algorithm', 'aes-gcm')
        
        # Active components
        active_hashes = [name for name in ['sha256', 'sha512', 'blake2b', 'blake3'] 
                        if config.get(f'{name}_rounds', 0) > 0]
        
        active_kdfs = []
        if config.get('pbkdf2_iterations', 0) > 0:
            active_kdfs.append('PBKDF2')
        if config.get('enable_argon2', False):
            active_kdfs.append('Argon2')
        if config.get('enable_scrypt', False):
            active_kdfs.append('Scrypt')
        
        return {
            'algorithm': algorithm,
            'active_hash_functions': active_hashes,
            'active_kdfs': active_kdfs,
            'post_quantum_enabled': bool(config.get('pqc_algorithm')),
            'security_level': security_analysis['overall']['level'].name,
            'overall_score': security_analysis['overall']['score'],
            'configuration_complexity': self._assess_complexity(config),
            'suitable_for': self._determine_suitability(security_analysis['overall']['level'])
        }
    
    def _assess_complexity(self, config: Dict[str, Any]) -> str:
        """Assess configuration complexity."""
        complexity_score = 0
        
        # Count active components
        if config.get('enable_argon2', False):
            complexity_score += 2
        if config.get('enable_scrypt', False):
            complexity_score += 1
        if config.get('pbkdf2_iterations', 0) > 0:
            complexity_score += 1
        
        # Count hash functions
        hash_count = sum(1 for name in ['sha256', 'sha512', 'blake2b', 'blake3'] 
                        if config.get(f'{name}_rounds', 0) > 0)
        complexity_score += hash_count
        
        # PQC adds complexity
        if config.get('pqc_algorithm'):
            complexity_score += 2
        
        if complexity_score <= 2:
            return "simple"
        elif complexity_score <= 5:
            return "moderate"
        elif complexity_score <= 8:
            return "complex"
        else:
            return "very_complex"
    
    def _determine_suitability(self, security_level: SecurityLevel) -> List[str]:
        """Determine what the configuration is suitable for."""
        suitability = []
        
        if security_level.value >= SecurityLevel.MODERATE.value:
            suitability.append("personal_files")
        
        if security_level.value >= SecurityLevel.GOOD.value:
            suitability.extend(["business_documents", "financial_data"])
        
        if security_level.value >= SecurityLevel.HIGH.value:
            suitability.extend(["sensitive_data", "compliance_requirements"])
        
        if security_level.value >= SecurityLevel.VERY_HIGH.value:
            suitability.extend(["classified_information", "long_term_archival"])
        
        return suitability


def analyze_configuration_from_args(args, use_case: Optional[str] = None) -> ConfigurationAnalysis:
    """
    Convenience function to analyze configuration from parsed arguments.
    
    Args:
        args: Parsed command line arguments
        use_case: Optional use case for context-aware analysis
        
    Returns:
        Complete configuration analysis
    """
    # Convert args to configuration dictionary
    config = vars(args)
    
    # Determine compliance requirements from use case or explicit settings
    compliance_requirements = []
    if use_case == 'compliance' or getattr(args, 'compliance_mode', False):
        compliance_requirements = ['fips_140_2', 'common_criteria']
    
    analyzer = ConfigurationAnalyzer()
    return analyzer.analyze_configuration(config, use_case, compliance_requirements)