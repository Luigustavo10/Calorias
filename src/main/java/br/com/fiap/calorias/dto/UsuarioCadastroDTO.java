package br.com.fiap.calorias.dto;

import br.com.fiap.calorias.model.UsuarioRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UsuarioCadastroDTO(
        Long usuarioId,

        @NotBlank(message = "O nome do usuário é obrigatório!") //Mostrando oq eh obrigatorio e o que nao é
        String nome,

        @NotBlank(message = "O e-mail do usuário é obrigatório!")
        @Email(message = "O e-mail do usuário não é válido!")// utiliza o padrão de e-mail
        String email,

        @NotBlank(message = "A senha é obrigatório")
        @Size(min = 6, max = 20, message = "A senha deve conter entre 6 e 20 caracteres!") //Mostra o tamanho do campo
        String senha,

        UsuarioRole role
) {
}