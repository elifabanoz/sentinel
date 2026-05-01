package io.sentinel.gateway.scan;

import io.sentinel.gateway.domain.Domain;
import io.sentinel.gateway.domain.DomainRepository;
import io.sentinel.gateway.user.User;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/scans")
public class ScanController {

    private static final List<String> SCAN_QUEUES = List.of(
            "scan.tls", "scan.sqli", "scan.xss", "scan.osint", "scan.deps"
    );

    private final ScanRepository scanRepository;
    private final DomainRepository domainRepository;
    private final FindingRepository findingRepository;
    private final RabbitTemplate rabbitTemplate;

    public ScanController(ScanRepository scanRepository,
                          DomainRepository domainRepository,
                          FindingRepository findingRepository,
                          RabbitTemplate rabbitTemplate) {
        this.scanRepository = scanRepository;
        this.domainRepository = domainRepository;
        this.findingRepository = findingRepository;
        this.rabbitTemplate = rabbitTemplate;
    }

    @GetMapping
    public List<ScanResponse> list(@AuthenticationPrincipal User user) {
        return scanRepository.findByUserIdOrderByStartedAtDesc(user.getId())
                .stream()
                .map(ScanResponse::from)
                .toList();
    }

    @PostMapping
    public ResponseEntity<?> create(@AuthenticationPrincipal User user,
                                    @Valid @RequestBody CreateScanRequest request) {
        Domain domain = domainRepository
                .findByIdAndUserIdAndStatus(request.domainId(), user.getId(), "VERIFIED")
                .orElse(null);

        if (domain == null) {
            return ResponseEntity.badRequest()
                    .body("Domain not found or not verified. Verify your domain before scanning.");
        }

        Scan scan = new Scan();
        scan.setDomain(domain);
        scan.setUser(user);
        scanRepository.save(scan);

        Map<String, String> jobMessage = Map.of(
                "scan_id", scan.getId().toString(),
                "url", "https://" + domain.getName(),
                "domain", domain.getName()
        );

        for (String queue : SCAN_QUEUES) {
            rabbitTemplate.convertAndSend(queue, jobMessage);
        }

        return ResponseEntity.accepted().body(new CreateScanResponse(
                scan.getId().toString(),
                "/scans/" + scan.getId() + "/status"
        ));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> get(@AuthenticationPrincipal User user,
                                 @PathVariable UUID id) {
        return scanRepository.findByIdAndUserId(id, user.getId())
                .map(scan -> ResponseEntity.ok(ScanResponse.from(scan)))
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/{id}/status")
    public ResponseEntity<?> status(@AuthenticationPrincipal User user,
                                    @PathVariable UUID id) {
        return scanRepository.findByIdAndUserId(id, user.getId())
                .map(scan -> ResponseEntity.ok(Map.of(
                        "scan_id", scan.getId().toString(),
                        "status", scan.getStatus(),
                        "progress", scan.getProgress()
                )))
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/{id}/findings")
    public ResponseEntity<?> findings(@AuthenticationPrincipal User user,
                                      @PathVariable UUID id) {
        return scanRepository.findByIdAndUserId(id, user.getId())
                .map(scan -> ResponseEntity.ok(
                        findingRepository.findByScanIdOrderByCvssScoreDesc(scan.getId())
                                .stream()
                                .map(f -> new FindingResponse(
                                        f.getId().toString(),
                                        f.getSeverity(),
                                        f.getOwaspCategory(),
                                        f.getTitle(),
                                        f.getDescription(),
                                        f.getEvidence(),
                                        f.getRemediation(),
                                        f.getCvssScore()
                                ))
                                .toList()
                ))
                .orElse(ResponseEntity.notFound().build());
    }

    record CreateScanRequest(@NotNull UUID domainId) {}

    record CreateScanResponse(String scanId, String statusUrl) {}

    record FindingResponse(String id, String severity, String owaspCategory,
                           String title, String description, String evidence,
                           String remediation, java.math.BigDecimal cvssScore) {}

    record ScanResponse(String id, String domainName, String status,
                        int progress, String startedAt, String finishedAt) {
        static ScanResponse from(Scan scan) {
            return new ScanResponse(
                    scan.getId().toString(),
                    scan.getDomain().getName(),
                    scan.getStatus(),
                    scan.getProgress(),
                    scan.getStartedAt().toString(),
                    scan.getFinishedAt() != null ? scan.getFinishedAt().toString() : null
            );
        }
    }
}
