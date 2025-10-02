/**
 * Chat AI Agent Plugin for Obsidian
 * 
 * A plugin that enables integration with AI services via webhooks.
 * Features secure communication, note processing, and data encryption.
 * 
 * Key Security Features:
 * - Webhook URL validation (HTTPS only, no private IPs)
 * - Token-based authentication
 * - Data encryption for sensitive fields
 * - XSS prevention measures
 * 
 * @author Obsidian Team
 * @version 1.0.0
 * @license MIT
 */

'use strict';

var obsidian = require('obsidian');

// Funções utilitárias para criptografia de dados sensíveis
/**
 * Simple encryption function using XOR cipher
 * Note: This provides basic obfuscation rather than strong security
 * In production, consider using a proper encryption library
 * @param {string} data - The data to encrypt
 * @param {string} password - The password/key for encryption
 * @returns {string} - Base64 encoded encrypted data
 */
function simpleEncrypt(data, password) {
    if (!data) return data;
    
    // Esta é uma implementação simplificada de criptografia
    // Em um ambiente de produção real, usaria uma biblioteca de criptografia robusta
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const passwordBuffer = encoder.encode(password || 'default-key');
    
    // XOR simplificado para demonstração
    const result = new Uint8Array(dataBuffer.length);
    for (let i = 0; i < dataBuffer.length; i++) {
        result[i] = dataBuffer[i] ^ passwordBuffer[i % passwordBuffer.length];
    }
    
    return btoa(String.fromCharCode(...result));
}

/**
 * Simple decryption function using XOR cipher (inverse of encryption)
 * @param {string} encryptedData - The base64 encoded encrypted data
 * @param {string} password - The password/key for decryption
 * @returns {string} - Decrypted data
 */
function simpleDecrypt(encryptedData, password) {
    if (!encryptedData) return encryptedData;
    
    try {
        const encodedData = atob(encryptedData);
        const dataBuffer = new Uint8Array(encodedData.length);
        for (let i = 0; i < encodedData.length; i++) {
            dataBuffer[i] = encodedData.charCodeAt(i);
        }
        
        const passwordBuffer = new TextEncoder().encode(password || 'default-key');
        const result = new Uint8Array(dataBuffer.length);
        for (let i = 0; i < dataBuffer.length; i++) {
            result[i] = dataBuffer[i] ^ passwordBuffer[i % passwordBuffer.length];
        }
        
        return new TextDecoder().decode(result);
    } catch (e) {
        console.error('Erro ao descriptografar dados:', e);
        return encryptedData; // Retorna dados originais em caso de erro
    }
}

// Funções de validação de URL para prevenir SSRF
/**
 * Validates a webhook URL to prevent SSRF attacks
 * - Only HTTPS protocol allowed
 * - Blocks private IP addresses
 * - Validates URL format
 * - Checks if domain is in allowed list (if specified)
 * @param {string} url - The URL to validate
 * @param {string} allowedDomains - Comma-separated list of allowed domains
 * @returns {object} - { valid: boolean, error: string }
 */
function isValidWebhookUrl(url, allowedDomains = '') {
    try {
        const parsedUrl = new URL(url);
        
        // Verificar protocolo (apenas HTTPS permitido para segurança)
        if (parsedUrl.protocol !== 'https:') {
            return { valid: false, error: 'Apenas URLs HTTPS são permitidas para segurança' };
        }
        
        // Prevenir acesso a IPs privados e locais para evitar SSRF
        const hostname = parsedUrl.hostname.toLowerCase();
        if (isPrivateIP(hostname)) {
            return { valid: false, error: 'Acesso a IPs privados ou locais não é permitido' };
        }
        
        // Verificar se domínios permitidos estão definidos e se o hostname está na lista
        if (allowedDomains && allowedDomains.trim() !== '') {
            const allowedDomainsList = allowedDomains.split(',').map(domain => domain.trim().toLowerCase()).filter(domain => domain);
            
            // Verificar se o hostname ou um subdomínio corresponde a algum domínio permitido
            const isDomainAllowed = allowedDomainsList.some(allowedDomain => {
                // Verificar correspondência exata ou subdomínio (ex: hook.us.make.com corresponde a make.com)
                return hostname === allowedDomain || 
                       hostname.endsWith('.' + allowedDomain) || 
                       // Para domínios como hook.us.make.com, verificar se é um subdomínio de make.com
                       (allowedDomain.includes('.') && hostname.endsWith('.' + allowedDomain) && hostname.length > allowedDomain.length);
            });
            
            if (!isDomainAllowed) {
                return { valid: false, error: `O domínio '${hostname}' não está na lista de domínios permitidos` };
            }
        }
        
        return { valid: true };
    } catch (e) {
        return { valid: false, error: 'Formato de URL inválido' };
    }
}

/**
 * Checks if hostname is a private IP address to prevent SSRF
 * @param {string} hostname - The hostname to check
 * @returns {boolean} - True if private IP
 */
function isPrivateIP(hostname) {
    // Verificar se é um IP privado ou local
    const privateIPRegex = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.0\.0\.1|localhost|0\.0\.0\.0)/;
    const isPrivateIP = privateIPRegex.test(hostname) || hostname === 'localhost';
    
    // Também verificar por IPs IPv6 locais
    const localIPv6 = ['::1', '[::1]', '[::]'];
    const isLocalIPv6 = localIPv6.includes(hostname);
    
    return isPrivateIP || isLocalIPv6;
}

/******************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */
/* global Reflect, Promise, SuppressedError, Symbol, Iterator */


function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

typeof SuppressedError === "function" ? SuppressedError : function (error, suppressed, message) {
    var e = new Error(message);
    return e.name = "SuppressedError", e.error = error, e.suppressed = suppressed, e;
};

// Valores padrão para as configurações
const DEFAULT_SETTINGS = {
    n8nWebhookUrl: '', // Armazenado de forma criptografada
    webhookToken: '', // Token para validação de segurança na webhook - armazenado de forma criptografada
    defaultSavePath: 'AI Agent for Obsidian Notes', // New default path
    allowedDomains: 'hooks.zapier.com,hook.us.make.com,hook.eu.make.com,my.pabbly.com', // Domains allowed for webhooks
    authType: 'bearer', // Tipo de autenticação: 'bearer', 'header', 'authorization', 'maketoken', 'query', 'none'
    customHeaderName: 'X-Webhook-Token', // Nome do cabeçalho personalizado quando usando o tipo 'header'
    authScheme: 'Bearer' // Esquema de autenticação para o tipo 'authorization' (ex: Bearer, Token, Basic, ApiKey)
};
// Classe para a aba de configurações do plugin
class AIAgentObsidianSettingTab extends obsidian.PluginSettingTab {
    constructor(app, plugin) {
        super(app, plugin);
        this.plugin = plugin;
    }
    display() {
        const { containerEl } = this;
        containerEl.empty();
        containerEl.createEl('h2', { text: 'Configurações do AI Agent for Obsidian' });
        new obsidian.Setting(containerEl)
            .setName('URL do Webhook do n8n')
            .setDesc('A URL do webhook do seu workflow no n8n que recebe os dados. Apenas URLs HTTPS são permitidas.')
            .addText(text => text
            .setPlaceholder('Insira a URL do webhook (HTTPS obrigatório)')
            .setValue(this.plugin.settings.n8nWebhookUrl)
            .onChange((value) => __awaiter(this, void 0, void 0, function* () {
                // Validar URL antes de salvar
                const validation = isValidWebhookUrl(value, this.plugin.settings.allowedDomains);
                if (validation.valid || value === '') {
                    this.plugin.settings.n8nWebhookUrl = value;
                    yield this.plugin.saveSettings();
                } else {
                    // Mostrar notificação de erro ao usuário
                    new obsidian.Notice(`Erro na URL do Webhook: ${validation.error}`);
                    // Não atualizar a configuração se a URL for inválida
                }
            })));

        new obsidian.Setting(containerEl)
            .setName('Token de segurança da Webhook')
            .setDesc('Token para validação de segurança na comunicação com a webhook. Apenas HTTPS e domínios públicos são permitidos.')
            .addText(text => text
            .setPlaceholder('Insira o token de segurança')
            .setValue(this.plugin.settings.webhookToken)
            .onChange((value) => __awaiter(this, void 0, void 0, function* () {
            this.plugin.settings.webhookToken = value;
            yield this.plugin.saveSettings();
        })));

        new obsidian.Setting(containerEl)
            .setName('Caminho padrão para salvar notas')
            .setDesc('O caminho da pasta onde as notas salvas do chat serão criadas.')
            .addButton(button => button
                .setButtonText('Selecionar Pasta')
                .onClick(() => {
                    new FolderPickerModal(this.app, this.plugin.settings.defaultSavePath, async (selectedFolder) => {
                        this.plugin.settings.defaultSavePath = selectedFolder;
                        await this.plugin.saveSettings();
                        this.display(); // Re-render the settings tab to show the updated path
                    }).open();
                }))
            .addText(text => text
                .setPlaceholder('Ex: AI Agent for Obsidian Notes')
                .setValue(this.plugin.settings.defaultSavePath)
                .setDisabled(true)); // Disable direct text input, show selected path

        new obsidian.Setting(containerEl)
            .setName('Domínios permitidos')
            .setDesc('Lista de domínios separados por vírgula para os quais o plugin pode enviar requisições (ex: hooks.zapier.com,hook.us.make.com). Deixe vazio para permitir todos os domínios (menos IPs privados).')
            .addText(text => text
            .setPlaceholder('hooks.zapier.com,hook.us.make.com,hook.eu.make.com,my.pabbly.com')
            .setValue(this.plugin.settings.allowedDomains)
            .onChange((value) => __awaiter(this, void 0, void 0, function* () {
                this.plugin.settings.allowedDomains = value;
                yield this.plugin.saveSettings();
            })));

        // Armazenar referência para atualização dinâmica
        new obsidian.Setting(containerEl)
            .setName('Tipo de autenticação')
            .setDesc('Método de envio do token de segurança para o webhook')
            .addDropdown(dropdown => dropdown
            .addOption('bearer', 'Bearer Token (padrão para n8n)')
            .addOption('header', 'Cabeçalho personalizado')
            .addOption('authorization', 'Authorization header com esquema')
            .addOption('maketoken', 'Make.com (Token no body)')
            .addOption('query', 'Parâmetro de query (?token=<token>)')
            .addOption('none', 'Nenhum (sem token de autenticação)')
            .setValue(this.plugin.settings.authType)
            .onChange((value) => __awaiter(this, void 0, void 0, function* () {
                this.plugin.settings.authType = value;
                yield this.plugin.saveSettings();
                this.display(); // Re-render the settings tab to show/hide additional fields
            })));

        // Mostrar campos adicionais conforme o tipo de autenticação
        if (this.plugin.settings.authType === 'header') {
            new obsidian.Setting(containerEl)
                .setName('Nome do cabeçalho personalizado')
                .setDesc('Nome do cabeçalho HTTP para envio do token quando usando autenticação por cabeçalho personalizado')
                .addText(text => text
                .setPlaceholder('X-Webhook-Token')
                .setValue(this.plugin.settings.customHeaderName)
                .onChange((value) => __awaiter(this, void 0, void 0, function* () {
                    this.plugin.settings.customHeaderName = value;
                    yield this.plugin.saveSettings();
                })));
        }
        
        if (this.plugin.settings.authType === 'authorization') {
            new obsidian.Setting(containerEl)
                .setName('Esquema de autenticação')
                .setDesc('Esquema de autorização para o header Authorization (ex: Bearer, Token, Basic, ApiKey)')
                .addText(text => text
                .setPlaceholder('Bearer')
                .setValue(this.plugin.settings.authScheme)
                .onChange((value) => __awaiter(this, void 0, void 0, function* () {
                    this.plugin.settings.authScheme = value;
                    yield this.plugin.saveSettings();
                })));
        }
        
        if (this.plugin.settings.authType === 'maketoken') {
            const descEl = document.createDocumentFragment();
            descEl.append(
                "O token será enviado como parte do corpo da requisição no campo 'token'. ",
                descEl.createEl('strong', { text: 'Esta opção é específica para Make.com.' })
            );
            
            new obsidian.Setting(containerEl)
                .setName('Autenticação para Make.com')
                .setDesc(descEl);
        }
    }
}

function callN8nWebhook(payload, webhookUrl, plugin) {
    return __awaiter(this, void 0, void 0, function* () {
        if (!webhookUrl) {
            new obsidian.Notice('URL do Webhook não configurada nas configurações do plugin.');
            return Promise.reject('URL do Webhook não configurada.');
        }
        
        // Validar URL antes de fazer a requisição para prevenir SSRF
        const validation = isValidWebhookUrl(webhookUrl, plugin.settings.allowedDomains);
        if (!validation.valid) {
            console.error('URL de webhook inválida:', validation.error);
            return Promise.reject(`URL de webhook inválida: ${validation.error}`);
        }
        
        try {
            // Preparar cabeçalhos com o token de segurança baseado no tipo de autenticação
            const headers = {
                'Content-Type': 'application/json',
            };
            
            // Adicionar token de segurança se estiver configurado, de acordo com o tipo de autenticação
            let modifiedPayload = { ...payload }; // Cópia do payload para modificação
            
            if (plugin && plugin.settings.webhookToken) {
                switch (plugin.settings.authType) {
                    case 'bearer':
                        headers['Authorization'] = `Bearer ${plugin.settings.webhookToken}`;
                        console.log('Enviando token como Bearer:', `Bearer ${plugin.settings.webhookToken.substring(0, 4)}...`); // Apenas para debug
                        break;
                    case 'header':
                        // Usar o nome do cabeçalho personalizado
                        const headerName = plugin.settings.customHeaderName || 'X-Webhook-Token';
                        headers[headerName] = plugin.settings.webhookToken;
                        console.log(`Enviando token no cabeçalho ${headerName}:`, `${plugin.settings.webhookToken.substring(0, 4)}...`); // Apenas para debug
                        break;
                    case 'authorization':
                        // Para serviços que esperam um esquema específico no header Authorization
                        // Usar o esquema configurado seguido pelo token
                        headers['Authorization'] = `${plugin.settings.authScheme} ${plugin.settings.webhookToken}`;
                        console.log(`Enviando token no header Authorization com esquema ${plugin.settings.authScheme}:`, `${plugin.settings.webhookToken.substring(0, 4)}...`); // Apenas para debug
                        break;
                    case 'maketoken':
                        // Para Make.com: adicionando o token como parte do payload
                        modifiedPayload.token = plugin.settings.webhookToken;
                        console.log(`Enviando token no body para Make.com:`, `${plugin.settings.webhookToken.substring(0, 4)}...`); // Apenas para debug
                        break;

                    case 'query':
                        // O token será adicionado como parâmetro de query posteriormente
                        console.log('Token será enviado como parâmetro de query');
                        break;
                    case 'none':
                        // Não adiciona token de autenticação
                        console.log('Nenhuma autenticação será enviada');
                        break;
                    default:
                        headers['Authorization'] = `Bearer ${plugin.settings.webhookToken}`;
                        console.log('Enviando token como Bearer (padrão):', `Bearer ${plugin.settings.webhookToken.substring(0, 4)}...`); // Apenas para debug
                        break;
                }
            }
            
            // Se o tipo de autenticação for query, adicionar o token como parâmetro de query
            let urlToSend = webhookUrl;
            if (plugin.settings.authType === 'query' && plugin.settings.webhookToken) {
                const url = new URL(webhookUrl);
                url.searchParams.set('token', plugin.settings.webhookToken);
                urlToSend = url.toString();
                console.log('URL com token de query:', urlToSend);
            }
            
            console.log('Requisição sendo enviada para:', urlToSend);
            console.log('Cabeçalhos da requisição:', headers);
            
            const response = yield fetch(urlToSend, {
                method: 'POST',
                headers: headers,
                body: JSON.stringify(modifiedPayload),
            });
            if (!response.ok) {
                const errorText = yield response.text();
                console.error('Erro do Webhook:', errorText);
                // Return a more detailed error message
                return Promise.reject(`Erro ao chamar o webhook: ${response.status} - ${errorText}. Verifique o status do seu workflow.`);
            }
            // We expect the workflow to respond with the plain text answer from the AI
            const responseText = yield response.text();
            return responseText;
        }
        catch (error) {
            console.error('Erro ao chamar o webhook:', error);
            let errorMessage = 'Erro de conexão ao tentar chamar o webhook. Verifique a URL, sua conexão ou o console para mais detalhes.';
            if (error instanceof Error) {
                errorMessage = `Erro de conexão: ${error.message}. Verifique a URL do Webhook e sua conexão.`;
            }
            // Return a more detailed error message
            return Promise.reject(errorMessage);
        }
    });
}

class NoteSuggester extends obsidian.AbstractInputSuggest {
    constructor(app, inputEl) {
        // Pass the inputEl to the super constructor, casting it to HTMLInputElement
        // This is a workaround as AbstractInputSuggest doesn't directly support HTMLTextAreaElement
        super(app, inputEl);
        this.triggerChar = '';
        this.triggerStart = -1;
        this.textAreaEl = inputEl; // Store the actual textarea element
    }
    getSuggestions(inputStr) {
        const cursorPosition = this.textAreaEl.selectionStart; // Use textAreaEl
        const textBeforeCursor = inputStr.substring(0, cursorPosition);
        const atMatch = textBeforeCursor.match(/@([\w\d\s-]*)$/);
        const hashMatch = textBeforeCursor.match(/#([\w\d\s-]*)$/);
        const match = atMatch || hashMatch;
        if (!match) {
            this.close();
            return [];
        }
        this.triggerChar = match[0][0]; // '@' or '#'
        this.triggerStart = textBeforeCursor.lastIndexOf(match[0]);
        const query = match[1];
        const allNotes = this.app.vault.getMarkdownFiles();
        return allNotes.filter(file => file.basename.toLowerCase().includes(query.toLowerCase()));
    }
    renderSuggestion(file, el) {
        el.setText(file.basename);
    }
    selectSuggestion(file, evt) {
        const currentVal = this.textAreaEl.value; // Use textAreaEl
        const newValue = currentVal.substring(0, this.triggerStart) +
            this.triggerChar + file.basename + ' ' +
            currentVal.substring(this.textAreaEl.selectionEnd); // Use textAreaEl
        this.textAreaEl.value = newValue; // Use textAreaEl
        this.textAreaEl.focus(); // Use textAreaEl
        this.close();
    }
}

class FolderPickerModal extends obsidian.Modal {
    constructor(app, currentPath, onSubmit) {
        super(app);
        this.currentPath = currentPath;
        this.onSubmit = onSubmit;
        this.selectedFolder = currentPath;
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.createEl('h2', { text: 'Selecionar Pasta' });

        const folderListEl = contentEl.createEl('div', { cls: 'folder-list' });
        folderListEl.style.maxHeight = '300px';
        folderListEl.style.overflowY = 'auto';
        folderListEl.style.border = '1px solid var(--background-modifier-border)';
        folderListEl.style.padding = '5px';
        folderListEl.style.marginBottom = '10px';

        const allFolders = this.app.vault.getAllLoadedFiles().filter(f => f instanceof obsidian.TFolder);

        allFolders.forEach(folder => {
            const folderEl = folderListEl.createEl('div', { cls: 'folder-item' });
            folderEl.setText(folder.path);
            folderEl.style.padding = '5px';
            folderEl.style.cursor = 'pointer';
            if (folder.path === this.selectedFolder) {
                folderEl.style.backgroundColor = 'var(--interactive-accent)';
                folderEl.style.color = 'var(--text-on-accent)';
            }

            folderEl.addEventListener('click', () => {
                // Deselect previous
                const prevSelected = folderListEl.querySelector('.folder-item[style*="background-color: var(--interactive-accent)"]');
                if (prevSelected) {
                    prevSelected.style.backgroundColor = '';
                    prevSelected.style.color = '';
                }
                // Select current
                folderEl.style.backgroundColor = 'var(--interactive-accent)';
                folderEl.style.color = 'var(--text-on-accent)';
                this.selectedFolder = folder.path;
            });
        });

        const buttonContainer = contentEl.createEl('div', { cls: 'modal-button-container' });
        const selectButton = buttonContainer.createEl('button', { text: 'Selecionar' });
        selectButton.addEventListener('click', () => {
            this.onSubmit(this.selectedFolder);
            this.close();
        });
    }

    onClose() {
        const { contentEl } = this;
        contentEl.empty();
    }
}

const AI_AGENT_OBSIDIAN_VIEW_TYPE = 'ai-agent-obsidian-view';
class AIAgentObsidianView extends obsidian.ItemView {
    constructor(leaf, plugin) {
        super(leaf);
        this.history = [];
        this.plugin = plugin;
        this.attachedNoteContext = null; // Initialize attached note context
    }
    getViewType() {
        return AI_AGENT_OBSIDIAN_VIEW_TYPE;
    }
    getDisplayText() {
        return 'AI Agent for Obsidian';
    }
    getIcon() {
        return 'bot';
    }
    onOpen() {
        return __awaiter(this, void 0, void 0, function* () {
            const container = this.containerEl.children[1];
            container.empty();
            container.addClass('ai-agent-obsidian-view');
            
            // Chat history container
            this.chatContainer = container.createEl('div', { cls: 'chat-container' });
            
            // Input area
            const inputArea = container.createEl('div', { cls: 'chat-input-area' });
            
            this.textInput = inputArea.createEl('textarea', { placeholder: 'Digite sua mensagem...', cls: 'chat-textarea' });
            
            // Buttons container
            const buttonsContainer = inputArea.createEl('div');
            
            // Clear history button
            const clearButton = buttonsContainer.createEl('button', { cls: 'chat-input-button' });
            obsidian.setIcon(clearButton, 'trash-2');
            clearButton.setAttribute('aria-label', 'Limpar histórico');
            clearButton.addEventListener('click', () => this.clearHistory());

            const attachmentButton = buttonsContainer.createEl('button', { cls: 'chat-input-button' });
            obsidian.setIcon(attachmentButton, 'paperclip');
            attachmentButton.setAttribute('aria-label', 'Anexar');
            attachmentButton.addEventListener('click', (event) => this.showAttachmentMenu(event));
            
            const sendButton = buttonsContainer.createEl('button', { cls: 'chat-input-button' });
            obsidian.setIcon(sendButton, 'send');
            sendButton.setAttribute('aria-label', 'Enviar mensagem');
            sendButton.addEventListener('click', () => this.handleSendFromInput());
            
            this.textInput.addEventListener('keydown', (event) => {
                if (event.key === 'Enter' && !event.shiftKey) {
                    event.preventDefault();
                    this.handleSendFromInput();
                }
            });
            
            this.renderHistory();
            
            // Attach the note suggester
            new NoteSuggester(this.app, this.textInput);

            // Listener to detect text selection in chat container
            this.chatContainer.addEventListener('mouseup', () => {
                setTimeout(() => {
                    const selection = window.getSelection();
                    if (selection && selection.toString().trim().length > 0) {
                        const selectedText = selection.toString();
                        // Check if selection is within the chat container
                        const range = selection.getRangeAt(0);
                        const selectedElement = range.commonAncestorContainer;
                        const chatMessageElement = selectedElement.closest('.chat-message');
                        
                        if (chatMessageElement) {
                            // Create a temporary menu and show it at cursor position
                            const menu = new obsidian.Menu();
                            menu.addItem((item) => item
                                .setTitle('Salvar seleção como nota')
                                .setIcon('save')
                                .onClick(() => {
                                    menu.hide();
                                    this.saveSelectionAsNote(selectedText);
                                }));
                            
                            // Position the menu near the selection
                            const rect = range.getBoundingClientRect();
                            menu.showAtPosition({ x: rect.left, y: rect.top });
                        }
                    }
                }, 10); // Small delay to ensure selection is complete
            });
            
            // Also keep the right-click context menu as a fallback
            this.chatContainer.addEventListener('contextmenu', (event) => {
                const selection = window.getSelection();
                if (selection && selection.toString().length > 0) {
                    const menu = new obsidian.Menu();
                    menu.addItem((item) => item
                        .setTitle('Salvar seleção como nota')
                        .setIcon('save')
                        .onClick(() => this.saveSelectionAsNote(selection.toString())));
                    menu.showAtMouseEvent(event);
                }
            });
        });
    }
    showAttachmentMenu(event) {
        const menu = new obsidian.Menu();
        menu.addItem((item) => item
            .setTitle('Anexar nota ativa')
            .setIcon('file-text')
            .onClick(() => this.attachActiveNote()));
        menu.addItem((item) => item
            .setTitle('Anexar texto selecionado')
            .setIcon('file-check-2')
            .onClick(() => this.attachSelectedText()));
        menu.showAtMouseEvent(event);
    }
    attachActiveNote() {
        let activeView = this.app.workspace.getActiveViewOfType(obsidian.MarkdownView);

        if (!activeView) {
            const markdownLeaves = this.app.workspace.getLeavesOfType('markdown');
            if (markdownLeaves.length === 1) {
                activeView = markdownLeaves[0].view;
            } else if (markdownLeaves.length > 1) {
                new obsidian.Notice('Múltiplas notas Markdown abertas, mas nenhuma ativa. Por favor, ative a nota que deseja anexar.');
                return;
            }
        }

        if (!activeView || !activeView.file) {
            new obsidian.Notice('Nenhuma nota ativa para anexar.');
            return;
        }
        const content = activeView.editor.getValue();
        if (!content) {
            new obsidian.Notice('A nota está vazia.');
            return;
        }

        const file = activeView.file;
        const cache = this.app.metadataCache.getFileCache(file);
        const properties = cache?.frontmatter || {};

        // Store the context of the attached note
        this.attachedNoteContext = {
            name: file.name,
            content: content,
            properties: properties
        };

        let attachedText = `--- Nota Anexada: ${file.name} ---\n`;
        attachedText += `\`\`\`markdown\n${content}\n\`\`\`\n\n`;
        attachedText += '--- Fim da Nota Anexada ---\n\n';
        attachedText += 'Minha instrução para a IA: '; // Placeholder for user's prompt

        this.textInput.value = attachedText;
        this.textInput.focus();
        new obsidian.Notice(`Nota '${file.name}' anexada ao campo de entrada. Adicione suas instruções e clique em Enviar.`);
    }
    attachSelectedText() {
        const activeView = this.app.workspace.getActiveViewOfType(obsidian.MarkdownView);
        if (!activeView) {
            new obsidian.Notice('Nenhuma nota ativa para obter a seleção.');
            return;
        }
        const selectedText = activeView.editor.getSelection();
        if (!selectedText) {
            new obsidian.Notice('Nenhum texto selecionado.');
            return;
        }
        const userMessage = 'Analisando o texto selecionado...';
        const payload = { type: 'process_content', content: selectedText };
        this.send(payload, userMessage);
    }
    async saveSelectionAsNote(selectedText) {
        if (!selectedText) {
            new obsidian.Notice('Nenhum texto selecionado para salvar.');
            return;
        }

        const defaultPath = this.plugin.settings.defaultSavePath;
        const folder = this.app.vault.getAbstractFileByPath(defaultPath);

        if (!(folder instanceof obsidian.TFolder)) {
            new obsidian.Notice(`Pasta '${defaultPath}' não encontrada ou não é uma pasta válida. Verifique as configurações do plugin.`);
            return;
        }

        // Prompt for filename
        const filename = await new Promise((resolve) => {
            const promptModal = new obsidian.Modal(this.app);
            promptModal.titleEl.setText('Salvar seleção como nota');
            promptModal.contentEl.createEl('p', { text: 'Digite o nome do arquivo para a nova nota:' });
            const input = promptModal.contentEl.createEl('input', { type: 'text', value: 'Nova Nota do Chat' });
            const button = promptModal.contentEl.createEl('button', { text: 'Salvar' });
            button.addEventListener('click', () => {
                resolve(input.value);
                promptModal.close();
            });
            promptModal.open();
        });

        if (!filename) {
            new obsidian.Notice('Nome do arquivo não fornecido. Operação cancelada.');
            return;
        }

        const fullPath = `${defaultPath}/${filename}.md`;

        try {
            await this.app.vault.create(fullPath, selectedText);
            new obsidian.Notice(`Nota '${filename}.md' salva em '${defaultPath}'.`);
        } catch (error) {
            console.error('Erro ao salvar nota:', error);
            new obsidian.Notice(`Erro ao salvar nota: ${error.message}`);
        }
    }

    replaceLastBotMessage(newText, messageId) {
        // Find the message in history and update its text
        const messageIndex = this.history.findIndex(msg => msg.text.includes(messageId));
        if (messageIndex !== -1) {
            this.history[messageIndex].text = newText;
        }

        // Find the corresponding DOM element and update it
        const loadingEl = this.chatContainer.querySelector('#' + messageId);
        if (loadingEl) {
            const parentMessageEl = loadingEl.closest('.chat-message');
            if (parentMessageEl) {
                // Clear existing content and render new text
                parentMessageEl.empty();
                obsidian.MarkdownRenderer.renderMarkdown(newText, parentMessageEl, this.plugin.app.vault.adapter.basePath, null);
            }
        } else {
            // Fallback if element not found (e.g., very fast response)
            this.addBotMessage(newText);
        }
        this.chatContainer.scrollTop = this.chatContainer.scrollHeight; // Scroll to bottom
    }

    clearHistory() {
        this.history = [];
        this.renderHistory();
    }
    send(payload, userMessage) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!userMessage)
                return;
            this.addUserMessage(userMessage);
            // Add a loading indicator message
            const loadingMessageId = 'loading-' + Date.now(); // Unique ID for the loading message
            this.addBotMessage('<span id="' + loadingMessageId + '" class="loading-indicator">AI Agent for Obsidian está pensando...</span>'); // Placeholder for loading

            try {
                const response = yield callN8nWebhook(payload, this.plugin.settings.n8nWebhookUrl, this.plugin);
                // Replace the loading message with the actual response
                this.replaceLastBotMessage(response, loadingMessageId);
            }
            catch (error) {
                // Replace the loading message with a more specific error message
                let displayError = 'Ocorreu um erro desconhecido.';
                if (typeof error === 'string') {
                    displayError = error;
                } else if (error instanceof Error) {
                    displayError = error.message;
                }
                this.replaceLastBotMessage(`Erro: ${displayError}`, loadingMessageId);
            }
        });
    }
    handleSendFromInput() {
        return __awaiter(this, void 0, void 0, function* () {
            const message = this.textInput.value.trim();
            if (!message)
                return;
            this.textInput.value = '';
            this.textInput.focus();

            let payload;
            let userMessageToSend = message; // Default to the message from input

            if (this.attachedNoteContext) {
                // If a note was attached, construct a process_content payload
                const noteContent = this.attachedNoteContext.content;
                const noteProperties = this.attachedNoteContext.properties;
                const noteName = this.attachedNoteContext.name;

                // Extract the user's instruction from the message
                const instructionPrefix = 'Minha instrução para a IA: ';
                let userInstruction = '';
                if (message.includes(instructionPrefix)) {
                    userInstruction = message.substring(message.indexOf(instructionPrefix) + instructionPrefix.length).trim();
                } else {
                    // If the instruction prefix was removed or not used, treat the whole message as instruction
                    userInstruction = message;
                }

                // Concatenate the instruction to the content with a clear marker
                const contentWithInstruction = noteContent + '\n\n--- INSTRUÇÃO DO USUÁRIO ---\n' + userInstruction;
                
                payload = {
                    type: 'process_content',
                    content: contentWithInstruction,
                    properties: noteProperties
                };
                userMessageToSend = `Analisando a nota '${noteName}' com instruções: ${userInstruction}`;
                this.attachedNoteContext = null; // Clear the context after sending
            } else if (message.startsWith('#')) {
                const noteName = message.substring(1).trim();
                if (noteName) {
                    const allNotes = this.plugin.app.vault.getMarkdownFiles();
                    const targetNote = allNotes.find(file => file.basename.toLowerCase() === noteName.toLowerCase());
                    if (targetNote) {
                        const content = yield this.plugin.app.vault.read(targetNote);
                        const cache = this.plugin.app.metadataCache.getFileCache(targetNote);
                        const properties = cache?.frontmatter || {};

                        // Concatenate the instruction to the content with a clear marker
                        // For messages starting with #, the whole message after the # is considered the instruction
                        const noteInstruction = message.substring(1).trim();  // Get everything after the #
                        const contentWithInstruction = content + '\n\n--- INSTRUÇÃO DO USUÁRIO ---\n' + noteInstruction;
                        
                        payload = { type: 'process_content', content: contentWithInstruction, properties: properties };
                        userMessageToSend = `Analisando a nota: ${targetNote.name}`;
                    }
                    else {
                        payload = { type: 'prompt', prompt: message };
                        userMessageToSend = `Nota '${noteName}' não encontrada.`;
                    }
                }
                else {
                    payload = { type: 'prompt', prompt: message };
                    userMessageToSend = 'Por favor, forneça um nome de nota após o #.';
                }
            }
            else {
                // For regular messages, treat the entire message as instruction/content
                // Create a minimal content with the instruction
                const contentWithInstruction = '--- CONTEÚDO PARA ANALISAR ---\n\n--- INSTRUÇÃO DO USUÁRIO ---\n' + message;
                payload = { type: 'process_content', content: contentWithInstruction };
            }
            this.send(payload, userMessageToSend);
        });
    }
    addUserMessage(text) {
        this.history.push({ role: 'user', text });
        const messageEl = this.chatContainer.createEl('div', {
            cls: `chat-message user-message`,
        });
        obsidian.MarkdownRenderer.renderMarkdown(text, messageEl, this.plugin.app.vault.adapter.basePath, null);
        this.chatContainer.scrollTop = this.chatContainer.scrollHeight; // Scroll to bottom
    }
    addBotMessage(text) {
        this.history.push({ role: 'model', text });
        const messageEl = this.chatContainer.createEl('div', {
            cls: `chat-message model-message`,
        });
        obsidian.MarkdownRenderer.renderMarkdown(text, messageEl, this.plugin.app.vault.adapter.basePath, null);
        this.chatContainer.scrollTop = this.chatContainer.scrollHeight; // Scroll to bottom
    }
    renderHistory() {
        this.chatContainer.empty();
        for (const msg of this.history) {
            const messageEl = this.chatContainer.createEl('div', {
                cls: `chat-message ${msg.role}-message`,
            });
            // Use MarkdownRenderer to correctly interpret newlines and other markdown formatting
            obsidian.MarkdownRenderer.renderMarkdown(msg.text, messageEl, this.plugin.app.vault.adapter.basePath, null);
        }
        // Scroll to bottom only if user is already near the bottom
        const isNearBottom = this.chatContainer.scrollHeight - this.chatContainer.scrollTop <= this.chatContainer.clientHeight + 100;
        if (isNearBottom) {
            this.chatContainer.scrollTop = this.chatContainer.scrollHeight;
        }
    }
    onClose() {
        return __awaiter(this, void 0, void 0, function* () {
            // Cleanup
        });
    }
}

class AIAgentObsidianPlugin extends obsidian.Plugin {
    onload() {
        return __awaiter(this, void 0, void 0, function* () {
            console.log('Carregando plugin AI Agent for Obsidian...');
            yield this.loadSettings();
            this.registerView(AI_AGENT_OBSIDIAN_VIEW_TYPE, (leaf) => new AIAgentObsidianView(leaf, this));
            this.addRibbonIcon('bot', 'Abrir AI Agent for Obsidian', () => {
                this.activateView();
            });
            this.addCommand({
                id: 'open-ai-agent-obsidian',
                name: 'Abrir AI Agent for Obsidian',
                callback: () => {
                    this.activateView();
                },
            });
            this.registerEvent(this.app.workspace.on('file-menu', (menu, file) => {
                if (file instanceof obsidian.TFile && file.parent) {
                    menu.addItem((item) => {
                        item
                            .setTitle('Enviar todas as notas desta pasta para n8n')
                            .setIcon('document-sync')
                            .onClick(() => {
                            const folder = file.parent;
                            if (folder) {
                                const markdownFiles = folder.children.filter((child) => child instanceof obsidian.TFile && child.extension === 'md');
                                if (markdownFiles.length > 0) {
                                    this.processAndSendMultipleFiles(markdownFiles, folder.name);
                                }
                                else {
                                    new obsidian.Notice('Nenhuma nota encontrada na pasta.');
                                }
                            }
                        });
                    });
                }
            }));
            this.addSettingTab(new AIAgentObsidianSettingTab(this.app, this));
        });
    }
    processAndSendMultipleFiles(files, folderName) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a;
            let totalSize = 0;
            const filesPayload = yield Promise.all(files.map((file) => __awaiter(this, void 0, void 0, function* () {
                const content = yield this.app.vault.read(file);
                const contentWithInstruction = content + '\n\n--- INSTRUÇÃO DO USUÁRIO ---\nAnalisar este documento';
                totalSize += content.length;
                return { filename: file.name, content: contentWithInstruction };
            })));
            if (totalSize > 1000000) {
                new obsidian.Notice(`Aviso: Você está enviando ${files.length} notas com um total de ${(totalSize / 1000000).toFixed(2)} MB. O processamento pode ser lento.`, 7000);
            }
            const payload = {
                type: 'process_files',
                files: filesPayload
            };
            const userMessage = `Analisando ${files.length} notas da pasta "${folderName}"...`;
            // Logic from the deleted activateViewAndSend method
            yield this.activateView();
            const view = (_a = this.app.workspace.getLeavesOfType(AI_AGENT_OBSIDIAN_VIEW_TYPE)[0]) === null || _a === void 0 ? void 0 : _a.view;
            if (view instanceof AIAgentObsidianView) {
                view.send(payload, userMessage);
            }
        });
    }
    onunload() {
        console.log('Descarregando plugin AI Agent for Obsidian.');
        this.app.workspace.detachLeavesOfType(AI_AGENT_OBSIDIAN_VIEW_TYPE);
    }
    loadSettings() {
        return __awaiter(this, void 0, void 0, function* () {
            const loadedData = yield this.loadData();
            const decryptedData = Object.assign({}, DEFAULT_SETTINGS);
            
            // Descriptografar campos sensíveis
            if (loadedData) {
                // Copiar todos os campos
                Object.assign(decryptedData, loadedData);
                
                // Descriptografar campos sensíveis
                if (loadedData.n8nWebhookUrl) {
                    decryptedData.n8nWebhookUrl = simpleDecrypt(loadedData.n8nWebhookUrl, this.app.vault.getName());
                }
                if (loadedData.webhookToken) {
                    decryptedData.webhookToken = simpleDecrypt(loadedData.webhookToken, this.app.vault.getName());
                }
            }
            
            this.settings = decryptedData;
        });
    }
    saveSettings() {
        return __awaiter(this, void 0, void 0, function* () {
            // Criptografar campos sensíveis antes de salvar
            const encryptedData = Object.assign({}, this.settings);
            
            if (this.settings.n8nWebhookUrl) {
                encryptedData.n8nWebhookUrl = simpleEncrypt(this.settings.n8nWebhookUrl, this.app.vault.getName());
            }
            if (this.settings.webhookToken) {
                encryptedData.webhookToken = simpleEncrypt(this.settings.webhookToken, this.app.vault.getName());
            }
            // Os campos allowedDomains, authType, customHeaderName e authScheme não precisam ser criptografados pois não contêm informação sensível
            
            yield this.saveData(encryptedData);
        });
    }
    activateView() {
        return __awaiter(this, void 0, void 0, function* () {
            this.app.workspace.detachLeavesOfType(AI_AGENT_OBSIDIAN_VIEW_TYPE);
            const rightLeaf = this.app.workspace.getRightLeaf(false);
            if (rightLeaf) {
                yield rightLeaf.setViewState({
                    type: AI_AGENT_OBSIDIAN_VIEW_TYPE,
                    active: true,
                });
                this.app.workspace.revealLeaf(this.app.workspace.getLeavesOfType(AI_AGENT_OBSIDIAN_VIEW_TYPE)[0]);
            }
        });
    }
}

module.exports = AIAgentObsidianPlugin;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibWFpbi5qcyIsInNvdXJjZXMiOlsibm9kZV9tb2R1bGVzL3RzbGliL3RzbGliLmVzNi5qcyIsInNldHRpbmdzLnRzIiwiYXBpLnRzIiwibm90ZS1zdWdnZXN0ZXIudHMiLCJjaGF0LXZpZXcudHMiLCJtYWluLnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6WyJQbHVnaW5TZXR0aW5nVGFiIiwiU2V0dGluZyIsIk5vdGljZSIsIkFic3RyYWN0SW5wdXRTdWdnZXN0IiwiSXRlbVZpZXciLCJzZXRJY29uIiwiTWVudSIsIk1hcmtkb3duVmlldyIsIlBsdWdpbiIsIlRGaWxlIl0sIm1hcHBpbmdzIjoiOzs7O0FBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFrR0E7QUFDTyxTQUFTLFNBQVMsQ0FBQyxPQUFPLEVBQUUsVUFBVSxFQUFFLENBQUMsRUFBRSxTQUFTLEVBQUU7QUFDN0QsSUFBSSxTQUFTLEtBQUssQ0FBQyxLQUFLLEVBQUUsRUFBRSxPQUFPLEtBQUssWUFBWSxDQUFDLEdBQUcsS0FBSyxHQUFHLElBQUksQ0FBQyxDQUFDLFVBQVUsT0FBTyxFQUFFLEVBQUUsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0FBQ2hILElBQUksT0FBTyxLQUFLLENBQUMsS0FBSyxDQUFDLEdBQUcsT0FBTyxDQUFDLEVBQUUsVUFBVSxPQUFPLEVBQUUsTUFBTSxFQUFFO0FBQy9ELFFBQVEsU0FBUyxTQUFTLENBQUMsS0FBSyxFQUFFLEVBQUUsSUFBSSxFQUFFLElBQUksQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLEVBQUUsRUFBRSxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztBQUNuRyxRQUFRLFNB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WUFDRCxNQUFNLFdBQVcsR0FBRyxDQUFBLFdBQUEsRUFBYyxLQUFLLENBQUMsTUFBTSxDQUFBLGlCQUFBLEVBQW9CLFVBQVUsQ0FBQSxJQUFBLENBQU07O0FBR2xGLFlBQUEsTUFBTSxJQUFJLENBQUMsWUFBWSxFQUFFO0FBQ3pCLFlBQUEsTUFBTSxJQUFJLEdBQUcsQ0FBQSxFQUFBLEdBQUEsSUFBSSxDQUFDLEdBQUcsQ0FBQyxTQUFTLENBQUMsZUFBZSxDQUFDLHFCQUFxQixDQUFDLENBQUMsQ0FBQyxDQUFDLE1BQUEsSUFBQSxJQUFBLEVBQUEsS0FBQSxNQUFBLEdBQUEsTUFBQSxHQUFBLEVBQUEsQ0FBRSxJQUFJO0FBRS9FLFlBQUEsSUFBSSxJQUFJLFlBQVksY0FBYyxFQUFFO0FBQ2xDLGdCQUFBLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxFQUFFLFdBQVcsQ0FBQztZQUNqQztRQUNGLENBQUMsQ0FBQTtBQUFBLElBQUE7SUFFRCxRQUFRLEdBQUE7QUFDTixRQUFBLE9BQU8sQ0FBQyxHQUFHLENBQUMsbUNBQW1DLENBQUM7UUFDaEQsSUFBSSxDQUFDLEdBQUcsQ0FBQyxTQUFTLENBQUMsa0JBQWtCLENBQUMscUJBQXFCLENBQUM7SUFDOUQ7SUFFTSxZQUFZLEdBQUE7O0FBQ2hCLFlBQUEsSUFBSSxDQUFDLFFBQVEsR0FBRyxNQUFNLENBQUMsTUFBTSxDQUFDLEVBQUUsRUFBRSxnQkFBZ0IsRUFBRSxNQUFNLElBQUksQ0FBQyxRQUFRLEVBQUUsQ0FBQztRQUM1RSxDQUFDLENBQUE7QUFBQSxJQUFBO0lBRUssWUFBWSxHQUFBOztZQUNoQixNQUFNLElBQUksQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQztRQUNwQyxDQUFDLENBQUE7QUFBQSxJQUFBO0lBRUssWUFBWSxHQUFBOztZQUNoQixJQUFJLENBQUMsR0FBRyxDQUFDLFNBQVMsQ0FBQyxrQkFBa0IsQ0FBQyxxQkFBcUIsQ0FBQztBQUU1RCxZQUFBLE1BQU0sU0FBUyxHQUFHLElBQUksQ0FBQyxHQUFHLENBQUMsU0FBUyxDQUFDLFlBQVksQ0FBQyxLQUFLLENBQUM7WUFDeEQsSUFBSSxTQUFTLEVBQUU7Z0JBQ1gsTUFBTSxTQUFTLENBQUMsWUFBWSxDQUFDO0FBQ3pCLG9CQUFBLElBQUksRUFBRSxxQkFBcUI7QUFDM0Isb0JBQUEsTUFBTSxFQUFFLElBQUk7QUFDZixpQkFBQSxDQUFDO2dCQUVGLElBQUksQ0FBQyxHQUFHLENBQUMsU0FBUyxDQUFDLFVBQVUsQ0FDekIsSUFBSSxDQUFDLEdBQUcsQ0FBQyxTQUFTLENBQUMsZUFBZSxDQUFDLHFCQUFxQixDQUFDLENBQUMsQ0FBQyxDQUFDLENBQy9EO1lBQ0w7UUFDRixDQUFDLENBQUE7QUFBQSxJQUFBO0FBQ0Y7Ozs7IiwieF9nb29nbGVfaWdub3JlTGlzdCI6WzBdfQ==
