package io.sentinel.gateway.domain;

import io.sentinel.gateway.user.User;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/domains")
public class DomainController {

    private final DomainRepository domainRepository;
    private final DnsVerificationService dnsVerificationService;

    public DomainController(DomainRepository domainRepository,
                            DnsVerificationService dnsVerificationService) {
        this.domainRepository = domainRepository;
        this.dnsVerificationService = dnsVerificationService;
    }

    @GetMapping
    public List<DomainResponse> list(@AuthenticationPrincipal User user) {
        return domainRepository.findByUserId(user.getId())
                .stream()
                .map(DomainResponse::from)
                .toList();
    }

    @PostMapping
    public ResponseEntity<?> add(@AuthenticationPrincipal User user,
                                 @Valid @RequestBody AddDomainRequest request) {
        if (domainRepository.existsByUserIdAndName(user.getId(), request.name())) {
            return ResponseEntity.badRequest().body("Domain already added");
        }

        Domain domain = new Domain();
        domain.setUser(user);
        domain.setName(request.name());
        domain.setVerificationToken("sentinel-verify-" + UUID.randomUUID().toString().substring(0, 8));
        domainRepository.save(domain);

        return ResponseEntity.ok(DomainResponse.from(domain));
    }

    @PostMapping("/{id}/verify")
    public ResponseEntity<?> verify(@AuthenticationPrincipal User user,
                                    @PathVariable UUID id) {
        Domain domain = domainRepository.findById(id)
                .filter(d -> d.getUser().getId().equals(user.getId()))
                .orElse(null);

        if (domain == null) {
            return ResponseEntity.notFound().build();
        }

        if (domain.isVerified()) {
            return ResponseEntity.ok(DomainResponse.from(domain));
        }

        boolean verified = dnsVerificationService.verifyTxtRecord(
                domain.getName(),
                domain.getVerificationToken()
        );

        if (!verified) {
            return ResponseEntity.badRequest()
                    .body("TXT record not found. Add: " + domain.getVerificationToken());
        }

        domain.setStatus("VERIFIED");
        domain.setVerifiedAt(Instant.now());
        domainRepository.save(domain);

        return ResponseEntity.ok(DomainResponse.from(domain));
    }

    record AddDomainRequest(@NotBlank String name) {}

    record DomainResponse(UUID id, String name, String status,
                          String verificationToken, String verifiedAt) {
        static DomainResponse from(Domain d) {
            return new DomainResponse(
                    d.getId(), d.getName(), d.getStatus(),
                    d.getVerificationToken(),
                    d.getVerifiedAt() != null ? d.getVerifiedAt().toString() : null
            );
        }
    }
}
