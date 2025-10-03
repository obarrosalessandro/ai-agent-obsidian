# AI Agent para Obsidian

Plugin poderoso do Obsidian que conecta com agentes de IA através de webhooks para uma experiência de chat inteligente dentro do Obsidian.

## Recursos

- **Chat com IA**: Integração perfeita com serviços de IA através de webhooks personalizáveis
- **Integração com Notas**: Anexe e processe notas existentes em seu vault
- **Comunicação Segura**: Implementa autenticação por token e validação de URL
- **Criptografia de Dados**: Informações sensíveis são armazenadas com criptografia básica
- **Exportar Notas**: Salve respostas da IA diretamente em seu vault
- **Processamento de Múltiplos Arquivos**: Envie todas as notas de uma pasta para fluxo de trabalho n8n

## Instalação

### Instalação Automática (quando disponível na loja oficial)
1. Abra as Configurações do Obsidian
2. Vá para "Plugins Comunitários"  
3. Pesquise por "AI Agent for Obsidian"
4. Instale e ative o plugin

### Instalação Manual (versão mais recente - GitHub)
1. Baixe os arquivos do plugin no GitHub:
   - Clique em "Code" → "Download ZIP" ou use o Git:
   - `git clone https://github.com/seu-usuario/ai-agent-obsidian.git`
2. Extraia os arquivos (se baixou ZIP) para uma pasta temporária
3. Navegue até a pasta do seu "Vault" do Obsidian
4. Entre na pasta `.obsidian/plugins/` (crie se não existir)
5. Crie uma nova pasta chamada `ai-agent-obsidian`
6. Copie todos os arquivos do plugin (main.js, manifest.json, styles.css) para esta pasta
7. Abra o Obsidian e vá para Configurações → Plugins Comunitários
8. Atualize a lista de plugins (botão "Atualizar lista")
9. Encontre "AI Agent for Obsidian" e habilite-o

## Configuração

1. Abra Configurações → AI Agent para Obsidian
2. Insira sua URL de webhook do n8n (HTTPS obrigatório)
3. Defina seu token de segurança (opcional mas recomendado)
4. Configure o caminho padrão para salvar notas

### Recursos de Segurança

- **Apenas HTTPS**: Apenas URLs HTTPS são aceitas para garantir comunicação segura
- **Bloqueio de IPs Privados**: Impede Server-Side Request Forgery (SSRF) bloqueando endereços IP privados
- **Autenticação por Token**: Autenticação opcional por token para requisições de webhook
- **Criptografia de Dados**: URLs de webhook e tokens são armazenados com criptografia básica

## Uso

### Chat Básico

1. Abra AI Agent para Obsidian na barra lateral
2. Digite sua mensagem na área de entrada
3. Clique em enviar ou pressione Enter (sem Shift)

### Processar Notas Existentes

- Use o ícone de clipe de papel para anexar a nota ativa à sua mensagem
- Clique com botão direito em qualquer nota no explorador de arquivos e selecione "Enviar todas as notas desta pasta para n8n" para processar múltiplos arquivos de uma vez

### Anexar Nota Ativa ou Texto Selecionado

- Clique no ícone de clipe de papel para anexar a nota ativa ou texto selecionado
- Selecione "Anexar nota ativa" ou "Anexar texto selecionado" no menu
- O conteúdo será pré-preenchido na área de entrada com espaço para instruções

### Anexar Texto Selecionado

- Selecione texto em qualquer nota
- Clique com botão direito e escolha "Enviar para AI Agent para Obsidian" no menu de contexto

### Exportar Respostas

- Clique com botão direito em qualquer resposta de IA no chat do AI Agent para Obsidian
- Selecione "Salvar seleção como nota" para salvar em seu vault

### Processar Múltiplos Arquivos

- Clique com botão direito em qualquer pasta no explorador de arquivos
- Selecione "Enviar todas as notas desta pasta para n8n"

## Requisitos

- Obsidian versão 1.6.0 ou superior
- Acesso a um endpoint de webhook (comumente implementado com n8n, Zapier, ou similar)

## Segurança

Este plugin implementa múltiplas medidas de segurança:
- Apenas URLs HTTPS são aceitas
- Endereços IP privados são bloqueados para prevenir SSRF
- Dados sensíveis são criptografados em repouso
- Autenticação opcional baseada em token para requisições de webhook

## Solução de Problemas

- Se chamadas de webhook falharem, verifique se sua URL usa HTTPS
- Certifique-se de que seu endpoint aceita requisições POST com payload JSON
- Verifique se seu token de segurança corresponde entre plugin e endpoint

## Suporte

Para problemas, dúvidas ou solicitações de recursos, por favor abra uma issue no repositório.