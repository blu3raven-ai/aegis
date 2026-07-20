// Prebuilt starter catalogs for the "Add Framework" flow. Control IDs match the
// identifiers the backend auto-mapper emits, so adding a template immediately
// surfaces any findings already mapped to that framework. Titles follow the
// published control language; admins can edit every field before saving.

export interface TemplateControl {
  control_id: string
  title: string
  description: string
  category: string
}

export interface FrameworkTemplate {
  id: string
  /** Short label for the picker chip (e.g. "SOC 2"). */
  short: string
  label: string
  description: string
  controls: TemplateControl[]
}

const SOC2: FrameworkTemplate = {
  id: "soc2",
  short: "SOC 2",
  label: "SOC 2 (Trust Services Criteria)",
  description:
    "AICPA Trust Services Criteria common controls covering logical access and system operations.",
  controls: [
    {
      control_id: "CC6.1",
      title: "Logical access controls",
      description:
        "Software, infrastructure, and architectures implement logical access controls to protect information assets.",
      category: "Logical & Physical Access",
    },
    {
      control_id: "CC6.6",
      title: "Boundary protection",
      description:
        "Logical access security measures protect against threats from sources outside the system boundaries.",
      category: "Logical & Physical Access",
    },
    {
      control_id: "CC6.7",
      title: "Restricting information movement",
      description:
        "Transmission, movement, and removal of information is restricted to authorized users and processes.",
      category: "Logical & Physical Access",
    },
    {
      control_id: "CC6.8",
      title: "Malicious software prevention",
      description:
        "Controls prevent or detect and act upon the introduction of unauthorized or malicious software.",
      category: "Logical & Physical Access",
    },
    {
      control_id: "CC7.1",
      title: "Vulnerability detection",
      description:
        "Detection and monitoring procedures identify changes and vulnerabilities in system configurations.",
      category: "System Operations",
    },
    {
      control_id: "CC7.2",
      title: "Security event monitoring",
      description:
        "System components are monitored for anomalies indicative of malicious acts, errors, and incidents.",
      category: "System Operations",
    },
  ],
}

const ISO27001: FrameworkTemplate = {
  id: "iso27001",
  short: "ISO 27001",
  label: "ISO/IEC 27001 (Annex A)",
  description:
    "Selected Annex A controls covering cloud usage, vulnerability, and configuration management.",
  controls: [
    {
      control_id: "A.5.23",
      title: "Information security for cloud services",
      description:
        "Acquisition, use, management, and exit from cloud services follow information security requirements.",
      category: "Organizational Controls",
    },
    {
      control_id: "A.8.8",
      title: "Management of technical vulnerabilities",
      description:
        "Information about technical vulnerabilities is obtained, exposure evaluated, and appropriate measures taken.",
      category: "Technological Controls",
    },
    {
      control_id: "A.8.9",
      title: "Configuration management",
      description:
        "Configurations of hardware, software, services, and networks are established, documented, and monitored.",
      category: "Technological Controls",
    },
    {
      control_id: "A.9.4",
      title: "System and application access control",
      description:
        "Access to information and application system functions is restricted in line with the access control policy.",
      category: "Access Control",
    },
  ],
}

const PCI_DSS: FrameworkTemplate = {
  id: "pci-dss",
  short: "PCI DSS",
  label: "PCI DSS v4.0",
  description:
    "Selected requirements covering secure development, vulnerability management, and authentication.",
  controls: [
    {
      control_id: "6.2.4",
      title: "Secure software engineering",
      description:
        "Software engineering techniques prevent or mitigate common software attacks in bespoke and custom software.",
      category: "Develop & Maintain Secure Systems",
    },
    {
      control_id: "6.3.1",
      title: "Identifying security vulnerabilities",
      description:
        "Security vulnerabilities are identified, assigned a risk ranking, and tracked to resolution.",
      category: "Develop & Maintain Secure Systems",
    },
    {
      control_id: "6.3.3",
      title: "Patching known vulnerabilities",
      description:
        "System components are protected from known vulnerabilities by installing applicable security patches.",
      category: "Develop & Maintain Secure Systems",
    },
    {
      control_id: "8.3.6",
      title: "Authentication credential strength",
      description:
        "Passwords and passphrases meet minimum strength and are protected during transmission and storage.",
      category: "Identify & Authenticate Access",
    },
    {
      control_id: "11.3.1",
      title: "Internal vulnerability scans",
      description:
        "Internal vulnerability scans are performed regularly and identified vulnerabilities are resolved.",
      category: "Test Security of Systems",
    },
  ],
}

/** Ordered catalog shown in the Add Framework template picker. */
export const FRAMEWORK_TEMPLATES: readonly FrameworkTemplate[] = [SOC2, ISO27001, PCI_DSS]
