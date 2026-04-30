package io.sentinel.gateway.scan;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ScanRepository extends JpaRepository<Scan, UUID> {

    List<Scan> findByUserIdOrderByStartedAtDesc(UUID userId);
    
    Optional<Scan> findByIdAndUserId(UUID id, UUID userId);
}
