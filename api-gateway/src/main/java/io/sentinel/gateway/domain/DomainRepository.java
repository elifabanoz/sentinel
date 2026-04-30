package io.sentinel.gateway.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface DomainRepository extends JpaRepository<Domain, UUID> {

    List<Domain> findByUserId(UUID userId);

    boolean existsByUserIdAndName(UUID userId, String name);

    Optional<Domain> findByIdAndUserIdAndStatus(UUID id, UUID userId, String status);
}
