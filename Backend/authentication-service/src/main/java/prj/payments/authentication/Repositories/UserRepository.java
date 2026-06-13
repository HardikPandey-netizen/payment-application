package prj.payments.authentication.Repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import prj.payments.authentication.Entity.AppUser;

public interface UserRepository extends JpaRepository<AppUser,Long> {
    AppUser findByUsername(String username);
    AppUser findByEmail(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}
