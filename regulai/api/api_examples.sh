#!/bin/bash

# RegulAI API - Ejemplos de uso con curl
# =========================================

# Configuración
API_URL="http://localhost:8000/api"
TOKEN=""

# Colores para output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== RegulAI API Examples ===${NC}\n"

# 1. Login
echo -e "${YELLOW}1. Login${NC}"
response=$(curl -s -X POST "${API_URL}/auth/login/" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin"
  }')
echo "$response" | python3 -m json.tool
TOKEN=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('token', ''))")
echo -e "Token: ${TOKEN}\n"

if [ -z "$TOKEN" ]; then
    echo "Error: No se pudo obtener el token. Verifica las credenciales."
    exit 1
fi

# 2. Obtener información del usuario actual
echo -e "${YELLOW}2. Obtener información del usuario actual${NC}"
curl -s -X GET "${API_URL}/auth/me/" \
  -H "Authorization: Token ${TOKEN}" | python3 -m json.tool
echo ""

# 3. Obtener estadísticas del dashboard
echo -e "${YELLOW}3. Obtener estadísticas del dashboard${NC}"
curl -s -X GET "${API_URL}/dashboard/stats/" \
  -H "Authorization: Token ${TOKEN}" | python3 -m json.tool
echo ""

# 4. Listar motores de IA disponibles
echo -e "${YELLOW}4. Listar motores de IA disponibles${NC}"
engines=$(curl -s -X GET "${API_URL}/company-engines/" \
  -H "Authorization: Token ${TOKEN}")
echo "$engines" | python3 -m json.tool
ENGINE_ID=$(echo "$engines" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['results'][0]['id'] if data.get('results') else '')" 2>/dev/null)
echo ""

# 5. Listar conversaciones
echo -e "${YELLOW}5. Listar conversaciones${NC}"
curl -s -X GET "${API_URL}/conversations/" \
  -H "Authorization: Token ${TOKEN}" | python3 -m json.tool
echo ""

# 6. Enviar mensaje de chat (nueva conversación)
echo -e "${YELLOW}6. Enviar mensaje de chat (nueva conversación)${NC}"
chat_response=$(curl -s -X POST "${API_URL}/chat/send/" \
  -H "Authorization: Token ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"content\": \"Hola, ¿cómo estás?\",
    \"engine_id\": ${ENGINE_ID:-1}
  }")
echo "$chat_response" | python3 -m json.tool
CONVERSATION_ID=$(echo "$chat_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('conversation_id', ''))")
echo ""

# 7. Continuar conversación
if [ ! -z "$CONVERSATION_ID" ]; then
    echo -e "${YELLOW}7. Continuar conversación${NC}"
    curl -s -X POST "${API_URL}/chat/send/" \
      -H "Authorization: Token ${TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{
        \"conversation_id\": ${CONVERSATION_ID},
        \"content\": \"Cuéntame un chiste\"
      }" | python3 -m json.tool
    echo ""
fi

# 8. Obtener mensajes de una conversación
if [ ! -z "$CONVERSATION_ID" ]; then
    echo -e "${YELLOW}8. Obtener mensajes de la conversación${NC}"
    curl -s -X GET "${API_URL}/conversations/${CONVERSATION_ID}/messages/" \
      -H "Authorization: Token ${TOKEN}" | python3 -m json.tool
    echo ""
fi

# 9. Listar alertas sin resolver
echo -e "${YELLOW}9. Listar alertas sin resolver${NC}"
curl -s -X GET "${API_URL}/alerts/unresolved/" \
  -H "Authorization: Token ${TOKEN}" | python3 -m json.tool
echo ""

# 10. Listar grupos de reglas
echo -e "${YELLOW}10. Listar grupos de reglas${NC}"
curl -s -X GET "${API_URL}/rules-groups/" \
  -H "Authorization: Token ${TOKEN}" | python3 -m json.tool
echo ""

# 11. Listar reglas
echo -e "${YELLOW}11. Listar reglas${NC}"
curl -s -X GET "${API_URL}/rules/" \
  -H "Authorization: Token ${TOKEN}" | python3 -m json.tool
echo ""

# 12. Listar departamentos
echo -e "${YELLOW}12. Listar departamentos${NC}"
curl -s -X GET "${API_URL}/departments/" \
  -H "Authorization: Token ${TOKEN}" | python3 -m json.tool
echo ""

# 13. Listar roles
echo -e "${YELLOW}13. Listar roles${NC}"
curl -s -X GET "${API_URL}/roles/" \
  -H "Authorization: Token ${TOKEN}" | python3 -m json.tool
echo ""

# 14. Logout
echo -e "${YELLOW}14. Logout${NC}"
curl -s -X POST "${API_URL}/auth/logout/" \
  -H "Authorization: Token ${TOKEN}" | python3 -m json.tool
echo ""

echo -e "${GREEN}=== Ejemplos completados ===${NC}"
