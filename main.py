from flask import Flask, request, jsonify
# Esta biblioteca utiliza o sistema de hashing para criptografar e verificar a senha do usuário
from werkzeug.security import generate_password_hash, check_password_hash
# A biblioteca JWT permite a verificação do usuário atravéz de tokens únicos.
import jwt
import datetime

app = Flask(__name__)

# Configuração da senha do usuário
app.config['SECRET_KEY'] = 'senha123456'

# Simulação de banco de dados
users_db = {}

def gerador_de_token(usuario, funcao):
    """Gera um token JWT com expiração de 1 hora."""
    informacoes = {
        'usuário': usuario,
        'funcao': funcao,
        'exp':  datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1) # tempo até expirar
    }
    token = jwt.encode(informacoes, app.config['SECRET_KEY'], algorithm='PBKDF2')
    return token

@app.route('/register', methods=['POST'])
def register():
    """Endpoint para registro de novos usuários."""
    data = request.json
    usuario = data.get('usuario')
    senha = data.get('senha')
    funcao = data.get('funcao', 'user')  # Padrão: "user"

    if usuario in users_db:
        return jsonify({'message': 'Usuário já existe'}), 400

    hashed_senha = generate_password_hash(senha)
    users_db[usuario] = {'senha': hashed_senha, 'funcao': funcao}
    return jsonify({'message': 'Usuário registrado com sucesso'}), 201

@app.route('/login', methods=['POST'])
def login():
    """Endpoint de login e geração de token JWT."""
    data = request.json
    usuario = data.get('usuario')
    senha = data.get('senha')

    user = users_db.get(usuario)
    if not user or not check_password_hash(user['senha'], senha):
        return jsonify({'message': 'Credenciais inválidas'}), 401

    token = gerador_de_token(usuario, user['funcao'])
    return jsonify({'token': token})

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

@app.route('/protected', methods=['GET'])
@token_required
def protected():
    """Endpoint protegido para usuários autenticados."""
    return jsonify({'message': f'Bem-vindo, {request.user["usuario"]}! Acesso autorizado.'})

@app.route('/admin', methods=['GET'])
@token_required
def admin_only():
    """Endpoint protegido apenas para administradores."""
    if request.user['funcao'] != 'admin':
        return jsonify({'message': 'Acesso negado. Apenas administradores.'}), 403

    return jsonify({'message': 'Bem-vindo ao painel administrativo!'})

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    """Simulação de recuperação de senha com link fictício."""
    data = request.json
    usuario = data.get('usuario')

    if usuario not in users_db:
        return jsonify({'message': 'Usuário não encontrado'}), 404

    reset_link = f'http://example.com/reset-password/{usuario}'
    return jsonify({'message': 'Link de redefinição enviado', 'link': reset_link})

if __name__ == '__main__':
    app.run(debug=True)