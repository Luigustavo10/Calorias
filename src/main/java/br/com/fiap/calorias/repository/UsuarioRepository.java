package br.com.fiap.calorias.repository;

import br.com.fiap.calorias.model.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public interface UsuarioRepository extends JpaRepository<Usuario, Long> {

    // Método para buscar um usuário pelo email
    Optional<Usuario> findByEmail(String email);
}


