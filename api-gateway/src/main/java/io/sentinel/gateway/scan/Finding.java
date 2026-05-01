package io.sentinel.gateway.scan;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "findings")
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_id", nullable = false)
    private Scan scan;

    @Column(nullable = false)
    private String severity;

    @Column(name = "owasp_category")
    private String owaspCategory;

    @Column(nullable = false)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(columnDefinition = "TEXT")
    private String evidence;

    @Column(columnDefinition = "TEXT")
    private String remediation;

    @Column(name = "cvss_score")
    private BigDecimal cvssScore;

    @Column(name = "created_at", updatable = false)
    private Instant createdAt = Instant.now();

    public UUID getId() { return id; }
    public Scan getScan() { return scan; }
    public String getSeverity() { return severity; }
    public String getOwaspCategory() { return owaspCategory; }
    public String getTitle() { return title; }
    public String getDescription() { return description; }
    public String getEvidence() { return evidence; }
    public String getRemediation() { return remediation; }
    public BigDecimal getCvssScore() { return cvssScore; }
    public Instant getCreatedAt() { return createdAt; }
}
