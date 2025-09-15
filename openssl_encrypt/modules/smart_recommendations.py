"""
Smart Recommendations Engine for OpenSSL Encrypt.

This module provides an intelligent recommendation system that analyzes user
context, security requirements, performance needs, and compliance requirements
to provide personalized, adaptive security recommendations.

The system integrates with all other modules to provide comprehensive
recommendations for encryption algorithms, security configurations, templates,
and best practices based on machine learning-inspired heuristics and
rule-based expert systems.

Design Philosophy:
- Context-aware recommendations based on usage patterns
- Adaptive learning from user choices and feedback
- Multi-dimensional analysis (security, performance, compliance, usability)
- Integration with existing analyzer and template systems
- Explainable recommendations with clear reasoning
"""

import json
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from .config_analyzer import ConfigurationAnalyzer
from .security_scorer import SecurityScorer
from .template_manager import TemplateManager


class RecommendationCategory(Enum):
    """Categories of recommendations."""
    
    SECURITY = "security"
    PERFORMANCE = "performance"
    COMPLIANCE = "compliance"
    USABILITY = "usability"
    ALGORITHM = "algorithm"
    TEMPLATE = "template"
    CONFIGURATION = "configuration"
    BEST_PRACTICE = "best_practice"


class ConfidenceLevel(Enum):
    """Confidence levels for recommendations."""
    
    VERY_LOW = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    VERY_HIGH = 5


class RecommendationPriority(Enum):
    """Priority levels for recommendations."""
    
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class UserContext:
    """User context information for personalized recommendations."""
    
    # Basic profile information
    user_type: str = "general"  # personal, business, developer, compliance_officer
    experience_level: str = "intermediate"  # beginner, intermediate, advanced, expert
    primary_use_cases: List[str] = field(default_factory=list)
    
    # Usage patterns
    typical_file_sizes: str = "mixed"  # small, medium, large, mixed
    frequency_of_use: str = "regular"  # occasional, regular, frequent, intensive
    performance_priority: str = "balanced"  # speed, security, balanced
    
    # Environment information
    target_platforms: List[str] = field(default_factory=lambda: ["linux"])
    network_constraints: bool = False
    storage_constraints: bool = False
    computational_constraints: bool = False
    
    # Compliance and security requirements
    compliance_requirements: List[str] = field(default_factory=list)
    security_clearance_level: str = "none"  # none, low, medium, high, top_secret
    data_sensitivity: str = "medium"  # low, medium, high, top_secret
    
    # Historical preferences (learned over time)
    preferred_algorithms: List[str] = field(default_factory=list)
    avoided_algorithms: List[str] = field(default_factory=list)
    preferred_templates: List[str] = field(default_factory=list)
    feedback_history: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SmartRecommendation:
    """A smart recommendation with detailed context and reasoning."""
    
    id: str
    category: RecommendationCategory
    priority: RecommendationPriority
    confidence: ConfidenceLevel
    
    title: str
    description: str
    action: str
    
    # Reasoning and explanation
    reasoning: str
    evidence: List[str]
    trade_offs: Dict[str, str]
    
    # Implementation details
    implementation_difficulty: str  # easy, medium, hard
    estimated_impact: str  # low, medium, high
    
    # Context information
    applicable_contexts: List[str]
    prerequisites: List[str] = field(default_factory=list)
    
    # Metadata
    created_at: str = field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S'))
    source_systems: List[str] = field(default_factory=list)
    
    # Feedback tracking
    user_accepted: Optional[bool] = None
    user_feedback: Optional[str] = None


class SmartRecommendationEngine:
    """
    Intelligent recommendation engine that provides context-aware security recommendations.
    
    This engine combines analysis from multiple systems to provide personalized,
    adaptive recommendations based on user context, historical patterns, and
    expert knowledge.
    """
    
    def __init__(self, data_dir: Optional[str] = None):
        """Initialize the smart recommendation engine."""
        self.config_analyzer = ConfigurationAnalyzer()
        self.security_scorer = SecurityScorer()
        self.template_manager = TemplateManager()
        
        # Set up data directory for storing user profiles and feedback
        if data_dir is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(current_dir)
            self.data_dir = os.path.join(project_root, "smart_recommendations_data")
        else:
            self.data_dir = data_dir
            
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Initialize knowledge base
        self._initialize_knowledge_base()
        
    def _initialize_knowledge_base(self):
        """Initialize the expert knowledge base with security best practices."""
        self.knowledge_base = {
            "algorithm_recommendations": {
                "personal_files": {
                    "recommended": ["aes-gcm", "xchacha20-poly1305", "fernet"],
                    "acceptable": ["chacha20-poly1305", "aes-gcm-siv"],
                    "discouraged": ["aes-ocb3", "camellia"]
                },
                "business_data": {
                    "recommended": ["aes-gcm", "aes-gcm-siv", "xchacha20-poly1305"],
                    "acceptable": ["chacha20-poly1305", "aes-siv"],
                    "discouraged": ["fernet", "aes-ocb3"]
                },
                "compliance_required": {
                    "recommended": ["aes-gcm", "aes-gcm-siv"],
                    "acceptable": ["aes-siv"],
                    "discouraged": ["fernet", "chacha20-poly1305", "xchacha20-poly1305"]
                },
                "archival_storage": {
                    "recommended": ["xchacha20-poly1305", "aes-gcm-siv"],
                    "acceptable": ["aes-gcm", "aes-siv"],
                    "discouraged": ["fernet", "aes-ocb3"]
                }
            },
            "security_thresholds": {
                "personal": {"minimum_score": 4.0, "recommended_score": 6.0},
                "business": {"minimum_score": 6.0, "recommended_score": 7.5},
                "compliance": {"minimum_score": 7.5, "recommended_score": 8.5},
                "archival": {"minimum_score": 8.0, "recommended_score": 9.0}
            },
            "performance_considerations": {
                "large_files": ["xchacha20-poly1305", "aes-gcm", "chacha20-poly1305"],
                "frequent_operations": ["fernet", "aes-gcm", "chacha20-poly1305"],
                "low_power_devices": ["chacha20-poly1305", "xchacha20-poly1305"],
                "network_transmission": ["aes-gcm", "chacha20-poly1305"]
            },
            "compliance_mappings": {
                "fips_140_2": ["aes-gcm", "aes-gcm-siv", "aes-siv"],
                "common_criteria": ["aes-gcm", "aes-gcm-siv"],
                "nist_guidelines": ["aes-gcm", "aes-gcm-siv", "aes-siv"]
            }
        }
        
    def generate_recommendations(
        self,
        user_context: UserContext,
        current_config: Optional[Dict[str, Any]] = None,
        specific_requirements: Optional[Dict[str, Any]] = None
    ) -> List[SmartRecommendation]:
        """Generate personalized smart recommendations based on user context."""
        recommendations = []
        
        # Analyze current configuration if provided
        current_analysis = None
        if current_config:
            try:
                current_analysis = self.config_analyzer.analyze_configuration(current_config)
            except Exception:
                pass
        
        # Generate different types of recommendations
        recommendations.extend(self._generate_security_recommendations(user_context, current_analysis))
        recommendations.extend(self._generate_algorithm_recommendations(user_context, current_config))
        recommendations.extend(self._generate_template_recommendations(user_context))
        recommendations.extend(self._generate_configuration_recommendations(user_context, current_analysis))
        recommendations.extend(self._generate_compliance_recommendations(user_context, current_analysis))
        recommendations.extend(self._generate_performance_recommendations(user_context, current_analysis))
        recommendations.extend(self._generate_best_practice_recommendations(user_context))
        
        # Apply user preferences and historical feedback
        recommendations = self._apply_user_preferences(recommendations, user_context)
        
        # Sort by priority and confidence
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        recommendations.sort(key=lambda r: (priority_order.get(r.priority.value, 5), -r.confidence.value))
        
        # Limit to most relevant recommendations
        return recommendations[:15]
        
    def _generate_security_recommendations(
        self, 
        user_context: UserContext, 
        current_analysis
    ) -> List[SmartRecommendation]:
        """Generate security-focused recommendations."""
        recommendations = []
        
        # Determine required security level based on context
        required_security = self._determine_required_security_level(user_context)
        
        if current_analysis:
            current_score = current_analysis.overall_score
            
            if current_score < required_security["minimum_score"]:
                recommendations.append(SmartRecommendation(
                    id="sec_001",
                    category=RecommendationCategory.SECURITY,
                    priority=RecommendationPriority.HIGH,
                    confidence=ConfidenceLevel.VERY_HIGH,
                    title="Security level below minimum requirements",
                    description=f"Current security score ({current_score:.1f}) is below the minimum recommended for {user_context.user_type} use cases ({required_security['minimum_score']:.1f})",
                    action="Upgrade to a higher security template or enable additional security features",
                    reasoning=f"Your {user_context.user_type} use case with {user_context.data_sensitivity} sensitivity data requires stronger security measures",
                    evidence=[
                        f"Current security score: {current_score:.1f}/10.0",
                        f"Required minimum: {required_security['minimum_score']:.1f}/10.0",
                        f"Data sensitivity: {user_context.data_sensitivity}"
                    ],
                    trade_offs={
                        "security": "Significantly improved protection against attacks",
                        "performance": "May reduce encryption/decryption speed by 10-30%",
                        "usability": "Minimal impact on ease of use"
                    },
                    implementation_difficulty="easy",
                    estimated_impact="high",
                    applicable_contexts=[user_context.user_type],
                    source_systems=["config_analyzer", "security_scorer"]
                ))
                
        # Check for specific security recommendations based on data sensitivity
        if user_context.data_sensitivity in ["high", "top_secret"]:
            recommendations.append(SmartRecommendation(
                id="sec_002",
                category=RecommendationCategory.SECURITY,
                priority=RecommendationPriority.HIGH,
                confidence=ConfidenceLevel.HIGH,
                title="Enable post-quantum encryption for sensitive data",
                description="Your data sensitivity level indicates you should consider post-quantum cryptography protection",
                action="Add --quantum-safe pq-high option to your encryption commands",
                reasoning="High sensitivity data should be protected against future quantum computing threats",
                evidence=[
                    f"Data sensitivity: {user_context.data_sensitivity}",
                    "Quantum computers may break current encryption within 10-20 years",
                    "Post-quantum algorithms provide future-proof security"
                ],
                trade_offs={
                    "security": "Protection against quantum computing attacks",
                    "performance": "20-40% slower encryption/decryption",
                    "compatibility": "May require newer software versions"
                },
                implementation_difficulty="easy",
                estimated_impact="medium",
                applicable_contexts=["business", "compliance", "archival"],
                source_systems=["smart_engine"]
            ))
            
        return recommendations
        
    def _generate_algorithm_recommendations(
        self,
        user_context: UserContext,
        current_config: Optional[Dict[str, Any]]
    ) -> List[SmartRecommendation]:
        """Generate algorithm-specific recommendations."""
        recommendations = []
        
        # Determine best algorithms for user context
        primary_use_case = user_context.primary_use_cases[0] if user_context.primary_use_cases else "personal"
        
        # Map use cases to knowledge base categories
        use_case_mapping = {
            "personal": "personal_files",
            "business": "business_data", 
            "compliance": "compliance_required",
            "archival": "archival_storage"
        }
        
        kb_category = use_case_mapping.get(primary_use_case, "personal_files")
        recommended_algorithms = self.knowledge_base["algorithm_recommendations"][kb_category]["recommended"]
        
        current_algorithm = None
        if current_config and "algorithm" in current_config:
            current_algorithm = current_config["algorithm"]
            
        # Recommend better algorithms if current one is suboptimal
        if current_algorithm and current_algorithm not in recommended_algorithms:
            best_algorithm = recommended_algorithms[0]
            
            recommendations.append(SmartRecommendation(
                id="alg_001",
                category=RecommendationCategory.ALGORITHM,
                priority=RecommendationPriority.MEDIUM,
                confidence=ConfidenceLevel.HIGH,
                title=f"Consider upgrading from {current_algorithm} to {best_algorithm}",
                description=f"Your current algorithm ({current_algorithm}) is not optimal for {primary_use_case} use cases",
                action=f"Use --algorithm {best_algorithm} for better security and performance",
                reasoning=f"Algorithm {best_algorithm} provides better security characteristics for {primary_use_case} applications",
                evidence=[
                    f"Current algorithm: {current_algorithm}",
                    f"Recommended for {primary_use_case}: {', '.join(recommended_algorithms)}",
                    f"Primary use case: {primary_use_case}"
                ],
                trade_offs={
                    "security": "Improved resistance to cryptanalytic attacks",
                    "performance": "Similar or better performance characteristics", 
                    "compatibility": "Widely supported across platforms"
                },
                implementation_difficulty="easy",
                estimated_impact="medium",
                applicable_contexts=[primary_use_case],
                source_systems=["smart_engine"]
            ))
            
        # Performance-based algorithm recommendations
        if user_context.typical_file_sizes == "large":
            fast_algorithms = self.knowledge_base["performance_considerations"]["large_files"]
            if current_algorithm and current_algorithm not in fast_algorithms:
                recommendations.append(SmartRecommendation(
                    id="alg_002", 
                    category=RecommendationCategory.PERFORMANCE,
                    priority=RecommendationPriority.MEDIUM,
                    confidence=ConfidenceLevel.MEDIUM,
                    title="Optimize algorithm for large file encryption",
                    description="For large files, stream ciphers typically offer better performance",
                    action=f"Consider using --algorithm {fast_algorithms[0]} for large files",
                    reasoning="Stream ciphers like XChaCha20-Poly1305 are optimized for large data volumes",
                    evidence=[
                        f"Typical file sizes: {user_context.typical_file_sizes}",
                        f"Performance-optimized algorithms: {', '.join(fast_algorithms)}",
                        "Stream ciphers avoid block padding overhead"
                    ],
                    trade_offs={
                        "performance": "20-50% faster for large files",
                        "security": "Equivalent or better security properties",
                        "memory": "Lower memory usage during encryption"
                    },
                    implementation_difficulty="easy",
                    estimated_impact="medium",
                    applicable_contexts=["large_files"],
                    source_systems=["smart_engine"]
                ))
                
        return recommendations
        
    def _generate_template_recommendations(self, user_context: UserContext) -> List[SmartRecommendation]:
        """Generate template-based recommendations."""
        recommendations = []
        
        primary_use_case = user_context.primary_use_cases[0] if user_context.primary_use_cases else "personal"
        
        # Get template recommendations from template manager
        template_recs = self.template_manager.recommend_templates(primary_use_case, max_results=2)
        
        for i, (template, reason) in enumerate(template_recs):
            recommendations.append(SmartRecommendation(
                id=f"tpl_{i+1:03d}",
                category=RecommendationCategory.TEMPLATE,
                priority=RecommendationPriority.MEDIUM,
                confidence=ConfidenceLevel.HIGH,
                title=f"Use '{template.metadata.name}' template for {primary_use_case} use case",
                description=f"{template.metadata.description}",
                action=f"Use --template {template.metadata.name.lower()} in your encryption commands",
                reasoning=reason,
                evidence=[
                    f"Security score: {template.metadata.security_score:.1f}/10.0",
                    f"Use cases: {', '.join(template.metadata.use_cases)}",
                    f"Tags: {', '.join(template.metadata.tags)}"
                ],
                trade_offs={
                    "convenience": "Pre-configured settings save time",
                    "customization": "Less flexibility than manual configuration",
                    "reliability": "Tested and validated configurations"
                },
                implementation_difficulty="easy",
                estimated_impact="medium",
                applicable_contexts=[primary_use_case],
                source_systems=["template_manager"]
            ))
            
        return recommendations
        
    def _generate_configuration_recommendations(
        self,
        user_context: UserContext,
        current_analysis
    ) -> List[SmartRecommendation]:
        """Generate configuration-specific recommendations."""
        recommendations = []
        
        if current_analysis:
            # Check for specific configuration improvements
            for rec in current_analysis.recommendations:
                if rec.priority.value in ["high", "critical"]:
                    recommendations.append(SmartRecommendation(
                        id=f"cfg_{rec.title.lower().replace(' ', '_')[:10]}",
                        category=RecommendationCategory.CONFIGURATION,
                        priority=RecommendationPriority(rec.priority.value),
                        confidence=ConfidenceLevel.HIGH,
                        title=rec.title,
                        description=rec.description,
                        action=rec.action,
                        reasoning=rec.rationale,
                        evidence=[
                            f"Configuration issue detected by analyzer",
                            f"Applies to: {', '.join(rec.applies_to)}",
                            f"Impact: {rec.impact}"
                        ],
                        trade_offs={
                            "security": rec.impact,
                            "implementation": "Configuration change required"
                        },
                        implementation_difficulty="medium",
                        estimated_impact="high",
                        applicable_contexts=rec.applies_to,
                        source_systems=["config_analyzer"]
                    ))
                    
        return recommendations
        
    def _generate_compliance_recommendations(
        self,
        user_context: UserContext,
        current_analysis
    ) -> List[SmartRecommendation]:
        """Generate compliance-specific recommendations."""
        recommendations = []
        
        if user_context.compliance_requirements:
            for framework in user_context.compliance_requirements:
                if framework in self.knowledge_base["compliance_mappings"]:
                    compliant_algorithms = self.knowledge_base["compliance_mappings"][framework]
                    
                    recommendations.append(SmartRecommendation(
                        id=f"cmp_{framework}",
                        category=RecommendationCategory.COMPLIANCE,
                        priority=RecommendationPriority.HIGH,
                        confidence=ConfidenceLevel.VERY_HIGH,
                        title=f"Ensure {framework.upper().replace('_', ' ')} compliance",
                        description=f"Your configuration should use algorithms approved for {framework} compliance",
                        action=f"Use algorithms: {', '.join(compliant_algorithms)}",
                        reasoning=f"Compliance with {framework} requires using approved cryptographic algorithms",
                        evidence=[
                            f"Compliance requirement: {framework}",
                            f"Approved algorithms: {', '.join(compliant_algorithms)}",
                            "Non-compliant algorithms may cause audit failures"
                        ],
                        trade_offs={
                            "compliance": "Meets regulatory requirements",
                            "algorithm_choice": "Limited to approved algorithms",
                            "audit": "Passes compliance audits"
                        },
                        implementation_difficulty="easy",
                        estimated_impact="high",
                        applicable_contexts=["compliance"],
                        prerequisites=[f"{framework} compliance requirement"],
                        source_systems=["smart_engine"]
                    ))
                    
        return recommendations
        
    def _generate_performance_recommendations(
        self,
        user_context: UserContext,
        current_analysis
    ) -> List[SmartRecommendation]:
        """Generate performance-specific recommendations."""
        recommendations = []
        
        if user_context.performance_priority == "speed":
            recommendations.append(SmartRecommendation(
                id="perf_001",
                category=RecommendationCategory.PERFORMANCE,
                priority=RecommendationPriority.MEDIUM,
                confidence=ConfidenceLevel.MEDIUM,
                title="Optimize for maximum encryption speed",
                description="Your performance priority is speed - consider lightweight algorithms",
                action="Use --fast alias or lightweight algorithms like ChaCha20-Poly1305",
                reasoning="You've indicated speed as your primary performance concern",
                evidence=[
                    f"Performance priority: {user_context.performance_priority}",
                    "Lightweight algorithms offer 2-5x faster encryption",
                    "Minimal security trade-off for most use cases"
                ],
                trade_offs={
                    "performance": "Significantly faster encryption/decryption",
                    "security": "Still provides strong security for most uses",
                    "battery": "Better for mobile/battery-powered devices"
                },
                implementation_difficulty="easy",
                estimated_impact="high",
                applicable_contexts=["speed_priority"],
                source_systems=["smart_engine"]
            ))
            
        elif user_context.computational_constraints:
            recommendations.append(SmartRecommendation(
                id="perf_002",
                category=RecommendationCategory.PERFORMANCE,
                priority=RecommendationPriority.MEDIUM,
                confidence=ConfidenceLevel.HIGH,
                title="Optimize for resource-constrained environment",
                description="Detected computational constraints - recommend efficient algorithms",
                action="Use ChaCha20-Poly1305 or reduce KDF iterations",
                reasoning="Computational constraints require optimized algorithms and parameters",
                evidence=[
                    "Computational constraints detected",
                    "ChaCha20 is optimized for low-resource environments",
                    "Reduced KDF iterations improve performance"
                ],
                trade_offs={
                    "performance": "Better performance on constrained systems",
                    "security": "Slight reduction in brute-force resistance",
                    "compatibility": "Good compatibility across devices"
                },
                implementation_difficulty="easy",
                estimated_impact="medium",
                applicable_contexts=["constrained_resources"],
                source_systems=["smart_engine"]
            ))
            
        return recommendations
        
    def _generate_best_practice_recommendations(self, user_context: UserContext) -> List[SmartRecommendation]:
        """Generate general best practice recommendations."""
        recommendations = []
        
        if user_context.experience_level in ["beginner", "intermediate"]:
            recommendations.append(SmartRecommendation(
                id="bp_001",
                category=RecommendationCategory.BEST_PRACTICE,
                priority=RecommendationPriority.LOW,
                confidence=ConfidenceLevel.MEDIUM,
                title="Use configuration wizard for guided setup",
                description="For easier configuration, use the built-in wizard",
                action="Run 'config-wizard' command to interactively configure security settings",
                reasoning="The wizard provides guided configuration appropriate for your experience level",
                evidence=[
                    f"Experience level: {user_context.experience_level}",
                    "Wizard reduces configuration errors",
                    "Provides explanations for each setting"
                ],
                trade_offs={
                    "usability": "Much easier configuration process",
                    "learning": "Educational explanations included",
                    "time": "Slightly longer than manual configuration"
                },
                implementation_difficulty="easy",
                estimated_impact="low",
                applicable_contexts=["beginner", "intermediate"],
                source_systems=["smart_engine"]
            ))
            
        recommendations.append(SmartRecommendation(
            id="bp_002",
            category=RecommendationCategory.BEST_PRACTICE,
            priority=RecommendationPriority.LOW,
            confidence=ConfidenceLevel.MEDIUM,
            title="Regularly analyze your security configuration",
            description="Periodically review and update your encryption settings",
            action="Use 'analyze-config' command monthly to check your configuration",
            reasoning="Cryptographic best practices and threats evolve over time",
            evidence=[
                "New vulnerabilities are discovered regularly",
                "Performance improvements are released frequently",
                "Compliance requirements may change"
            ],
            trade_offs={
                "security": "Stay current with latest security practices",
                "maintenance": "Requires periodic attention",
                "compliance": "Helps maintain regulatory compliance"
            },
            implementation_difficulty="easy",
            estimated_impact="medium",
            applicable_contexts=["all"],
            source_systems=["smart_engine"]
        ))
        
        return recommendations
        
    def _determine_required_security_level(self, user_context: UserContext) -> Dict[str, float]:
        """Determine required security levels based on user context."""
        base_requirements = self.knowledge_base["security_thresholds"]
        
        # Start with base requirements for user type
        primary_use_case = user_context.primary_use_cases[0] if user_context.primary_use_cases else "personal"
        requirements = base_requirements.get(primary_use_case, base_requirements["personal"]).copy()
        
        # Adjust based on data sensitivity
        sensitivity_multipliers = {
            "low": 0.8,
            "medium": 1.0,
            "high": 1.2,
            "top_secret": 1.5
        }
        
        multiplier = sensitivity_multipliers.get(user_context.data_sensitivity, 1.0)
        requirements["minimum_score"] *= multiplier
        requirements["recommended_score"] *= multiplier
        
        # Cap at maximum possible score
        requirements["minimum_score"] = min(requirements["minimum_score"], 10.0)
        requirements["recommended_score"] = min(requirements["recommended_score"], 10.0)
        
        return requirements
        
    def _apply_user_preferences(
        self,
        recommendations: List[SmartRecommendation],
        user_context: UserContext
    ) -> List[SmartRecommendation]:
        """Apply user preferences and historical feedback to recommendations."""
        filtered_recommendations = []
        
        for rec in recommendations:
            # Skip recommendations for avoided algorithms
            skip = False
            for avoided in user_context.avoided_algorithms:
                if avoided.lower() in rec.action.lower():
                    skip = True
                    break
                    
            if skip:
                continue
                
            # Boost confidence for preferred algorithms
            for preferred in user_context.preferred_algorithms:
                if preferred.lower() in rec.action.lower():
                    if rec.confidence.value < 5:
                        rec.confidence = ConfidenceLevel(rec.confidence.value + 1)
                    break
                    
            # Apply historical feedback
            if rec.id in user_context.feedback_history:
                feedback = user_context.feedback_history[rec.id]
                if feedback.get("user_accepted") is False:
                    # Lower confidence for previously rejected recommendations
                    if rec.confidence.value > 1:
                        rec.confidence = ConfidenceLevel(rec.confidence.value - 1)
                        
            filtered_recommendations.append(rec)
            
        return filtered_recommendations
        
    def save_user_context(self, user_id: str, user_context: UserContext):
        """Save user context for future recommendations."""
        context_file = os.path.join(self.data_dir, f"user_{user_id}_context.json")
        
        # Convert context to dictionary
        context_dict = {
            "user_type": user_context.user_type,
            "experience_level": user_context.experience_level,
            "primary_use_cases": user_context.primary_use_cases,
            "typical_file_sizes": user_context.typical_file_sizes,
            "frequency_of_use": user_context.frequency_of_use,
            "performance_priority": user_context.performance_priority,
            "target_platforms": user_context.target_platforms,
            "network_constraints": user_context.network_constraints,
            "storage_constraints": user_context.storage_constraints,
            "computational_constraints": user_context.computational_constraints,
            "compliance_requirements": user_context.compliance_requirements,
            "security_clearance_level": user_context.security_clearance_level,
            "data_sensitivity": user_context.data_sensitivity,
            "preferred_algorithms": user_context.preferred_algorithms,
            "avoided_algorithms": user_context.avoided_algorithms,
            "preferred_templates": user_context.preferred_templates,
            "feedback_history": user_context.feedback_history
        }
        
        with open(context_file, 'w') as f:
            json.dump(context_dict, f, indent=2)
            
    def load_user_context(self, user_id: str) -> Optional[UserContext]:
        """Load user context from saved data."""
        context_file = os.path.join(self.data_dir, f"user_{user_id}_context.json")
        
        if not os.path.exists(context_file):
            return None
            
        try:
            with open(context_file, 'r') as f:
                context_dict = json.load(f)
                
            return UserContext(**context_dict)
        except Exception:
            return None
            
    def record_feedback(
        self,
        user_id: str,
        recommendation_id: str,
        accepted: bool,
        feedback_text: Optional[str] = None
    ):
        """Record user feedback on recommendations for learning."""
        # Load current context
        user_context = self.load_user_context(user_id)
        if not user_context:
            user_context = UserContext()
            
        # Record feedback
        user_context.feedback_history[recommendation_id] = {
            "user_accepted": accepted,
            "user_feedback": feedback_text,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Save updated context
        self.save_user_context(user_id, user_context)
        
    def get_quick_recommendations(self, use_case: str, experience_level: str = "intermediate") -> List[str]:
        """Get quick text recommendations for immediate use."""
        user_context = UserContext(
            user_type="general",
            experience_level=experience_level,
            primary_use_cases=[use_case]
        )
        
        recommendations = self.generate_recommendations(user_context)
        
        # Extract top 5 actionable recommendations
        quick_recs = []
        for rec in recommendations[:5]:
            if rec.priority.value in ["high", "critical", "medium"]:
                quick_recs.append(f"💡 {rec.title}: {rec.action}")
                
        return quick_recs


def create_smart_recommendation_engine(data_dir: Optional[str] = None) -> SmartRecommendationEngine:
    """Factory function to create a smart recommendation engine."""
    return SmartRecommendationEngine(data_dir)