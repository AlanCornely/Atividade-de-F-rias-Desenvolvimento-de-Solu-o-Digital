# Snippet de validação de senha

Este snippet tem como intuito de ser facilmente incrementado e manter se utilizavel em vários apps.

O código utiliza sistemas de tokens para validação e um sistema de criptografia para as senhas do usuário.

## Método de criptografia:

O código utiliza a bibliotéca 'werkzeug.security' para fazer o hash da senha e criptografar.
Para demonstração no código foi colocado uma senha pré definida mas pode ser substituida com a incrementação de um banco de dados.

```python
  # Configuração da senha do usuário
  app.config['SECRET_KEY'] = 'senha123456'
```

O snippet utiliza o token para criptografar a senha do usuário utilizando um sistema de algoritimo que pode ser mudado.

```python
  token = jwt.encode(informacoes, app.config['SECRET_KEY'], algorithm='PBKDF2')
```
## Registro de usuários

Para efetuar o Registo de usuários é utilizado o métodos post para registrar no banco de dados os campos de usuário, senha e função.
```python
  @app.route('/register', methods=['POST'])
def register():
    """Endpoint para registro de novos usuários."""
    data = request.json
    usuario = data.get('usuario')
    senha = data.get('senha')
    funcao = data.get('funcao', 'user')  # Padrão: "user"

    if usuario in users_db:
        return jsonify({'message': 'Usuário já existe'}), 400
```

## Login

O sistema de login pede as credenciais de usuário e faz uma validação com o banco de dados.
```python
@app.route('/login', methods=['POST'])
def login():
    """Endpoint de login e geração de token JWT."""
    data = request.json
    usuario = data.get('usuario')
    senha = data.get('senha')

    user = users_db.get(usuario)
    if not user or not check_password_hash(user['senha'], senha):
        return jsonify({'message': 'Credenciais inválidas'}), 401
```
## Verificação de token

O código abaixo intercepta as comunicações para fazer a validação de token para saber se o token realmente existe ou se está ativo.
```python
  def token_required(f):
    """Middleware para verificar a autenticidade do token JWT.""" # O middleware intercepta as requisições antes de chegarem na função principal
    # O wrapper passa uma verificação lógica por cima da interceptação que será feita
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token é necessário'}), 403

        try:
            decoded_token = jwt.decode(token.split(" ")[1], app.config['SECRET_KEY'], algorithms=['PBKDF2'])
            request.user = decoded_token
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido'}), 401

        return f(*args, **kwargs)
    return wrapper
```

## Admin

Acesso somente para o pessoal cujo a função seja igual a de um admin.

```python
  @app.route('/admin', methods=['GET'])
@token_required
def admin_only():
    """Endpoint protegido apenas para administradores."""
    if request.user['funcao'] != 'admin':
        return jsonify({'message': 'Acesso negado. Apenas administradores.'}), 403

    return jsonify({'message': 'Bem-vindo ao painel administrativo!'})
```

## Recuperação de senha

  A recuperação de senha será feita por link externo com base no nome do usuário.

```python
  @app.route('/forgot-password', methods=['POST'])
def forgot_password():
    """Simulação de recuperação de senha com link fictício."""
    data = request.json
    usuario = data.get('usuario')

    if usuario not in users_db:
        return jsonify({'message': 'Usuário não encontrado'}), 404

    reset_link = f'http://example.com/reset-password/{usuario}'
    return jsonify({'message': 'Link de redefinição enviado', 'link': reset_link})
```
