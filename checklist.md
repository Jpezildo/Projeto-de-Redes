
## Validação complementar — NetProbe Wi-Fi

### Inventário de dispositivos

- [ ] Executar a descoberta ICMP em uma rede autorizada.
- [ ] Confirmar a identificação dos dispositivos que respondem ao ping.
- [ ] Confirmar a descoberta por ARP de dispositivos que não respondem ao ICMP.
- [ ] Conferir a associação entre IPv4 e endereço MAC.

### Portas TCP

- [ ] Identificar uma porta TCP aberta em um dispositivo de teste.
- [ ] Interromper o serviço e verificar a alteração do resultado.
- [ ] Reiniciar o serviço e confirmar a identificação da porta.
- [ ] Testar uma porta fora do intervalo definido.

### Validação de parâmetros

- [ ] Testar um timeout diferente do padrão.
- [ ] Testar uma entrada inválida.
- [ ] Registrar a duração da varredura.

### Interface

- [ ] Conferir o status dos dispositivos durante a execução.
- [ ] Conferir a apresentação dos IPs sem resposta.
- [ ] Repetir o teste na rede real.

### Evidências


- [ ] Criar uma matriz de testes.
- [ ] Registrar data, responsável e resultado.
- [ ] Adicionar captura de pacotes ARP reduzida.
=======
**Objetivo:** Deixar um ponto de partida único para o grupo, com código, documentação, dependências e evidências organizados.

**Passo a passo**
- [x] Criar a pasta `src/` para os três programas Python e `docs/` para topologia e evidências.
- [x] Adicionar `requirements.txt` com `flask`, `requests`, `dnslib`, `scapy` e `tabulate`. Congelar versões depois do primeiro teste funcional.
- [x] Criar `README.md` com o objetivo do tema 4.1, pré-requisitos e como iniciar cada programa.
- [x] Incluir `.gitignore` para `.venv/`, `__pycache__/`, `*.pyc` e arquivos temporários de captura.
- [ ] Subir este `checklist.md` na raiz e definir a convenção de atualização: marcar tarefas após validação e citar o PR/commit.

**Critérios de aceite**
- [x] Estrutura inicial organizada, com `src/`, `tools/`, `docs/`, evidências e testes.
- [x] Dependências Python declaradas para HTTP/DNS e NetProbe.
- [x] README documentado e execução atualizada para `python tools/netprobe.py`.
- [x] `.gitignore` configurado para ambientes, caches e artefatos locais.
- [x] Ferramenta legada NetProbe preservada integralmente em `tools/netprobe.py`.
- [x] Validações estáticas concluídas sem executar lógica de rede.
- [ ] Árvore de pastas está no GitHub e outros integrantes conseguem clonar.
- [x] `pip install -r requirements.txt` instala as bibliotecas em ambiente limpo.
- [x] README e checklist aparecem na raiz do repositório.

**Evidência esperada:** Captura da estrutura do repositório e link do commit inicial.

**Notas / PR / commit:** Validação local em 23/11/2026, Windows (build 26200), Python 3.12.10. Ambiente `.venv` novo e isolado (`include-system-site-packages = false`). `py -3.12 -m venv .venv` e `.\.venv\Scripts\python.exe -m pip install -r requirements.txt` concluídos; `pip check` sem conflitos; importações de `flask`, `requests` e `dnslib` aprovadas. Versões observadas: Flask 3.1.3, requests 2.34.2 e dnslib 0.9.26 (ainda não congeladas). Estrutura, links relativos e regras de ignore verificados. `git diff --check` sem erros; arquivos novos também inspecionados, pois ainda não estão rastreados.

A primeira criação da `.venv` falhou por bloqueio de acesso à pasta temporária do `ensurepip` no sandbox; a repetição com permissão ampliada foi bem-sucedida. Linux, Python 3.11 e testes funcionais não foram executados. Nenhum serviço ou captura foi iniciado.

**Revisão incremental — integração do NetProbe (23/11/2026):** arquivo movido da raiz para `tools/netprobe.py`, preservando o conteúdo byte a byte (SHA-256 `44625e9829fcbd9ba94ef56c430462cff07a5054c590d4740bf85ee1ff5819d8`). Incluídos `scapy` e `tabulate` em `requirements.txt`; a instalação foi validada na `.venv` existente, sem recriá-la. Scapy 2.8.0 e tabulate 0.10.0 instalados; as três dependências anteriores foram mantidas. Importações das cinco bibliotecas e `pip check` aprovados em Python 3.12.10. Os metadados das bibliotecas que declaram `Requires-Python` permitem Python 3.11; dnslib não declara esse campo. Não houve execução em Python 3.11 nem Linux.

A sintaxe de `tools/netprobe.py` foi validada com `compile(..., 'exec')`, sem executar o objeto compilado. A análise AST confirmou que as dependências externas do script estão declaradas. Caminho de execução e links relativos conferidos. O README documenta Npcap, permissões, limites e observações técnicas do legado. Não houve execução do módulo/`main()`, sondagens, instalação de drivers ou alteração de firewall. A importação básica de `scapy` não valida o driver nem o envio de pacotes. As Issues #02–#14 permanecem intactas.

**Status da Issue #01:** parcialmente concluída segundo os critérios originais: implementação e validação local prontas; publicação da árvore/checklist, link do commit e confirmação por outro integrante continuam pendentes. Não houve commit ou push. Atualizar os checkboxes somente após validação e registrar o PR/commit correspondente.

---

### ISSUE #02 — Configurar as máquinas e a rede

**Área:** Infraestrutura  
**Prioridade:** Crítica · **Dificuldade:** Baixa · **Esforço estimado:** 45–90 min  
**Dependências:** #01 · **Responsável:** _a definir_ · **Prazo:** _a definir_  

**Objetivo:** Garantir que A e B troquem pacotes reais, identificáveis pelo Wireshark.

**Preparação documental — 23/11/2026**

- [x] Criar [manual reproduzível Windows/Linux](docs/preparacao-ambiente.md) com identificação de IPs, conectividade, portas, firewall, Wireshark e troubleshooting.
- [x] Complementar a [topologia](docs/topologia.md) com campos pendentes por máquina, interfaces, evidências, data e responsável.
- [x] Registrar diagnóstico local de leitura e suas limitações, separado das máquinas reais.
- [x] Disponibilizar matriz de validação e link no README.

**Status da Issue #02:** preparação documental concluída; configuração e validação nas máquinas do laboratório pendentes. Nenhum teste A/B foi executado. O ambiente Codex não foi atribuído a A ou B. Nenhuma regra de firewall, serviço ou captura foi iniciada; NetProbe não foi executado nem alterado. A validação funcional de TCP/80 e UDP/53 depende dos servidores das Issues #03/#04; confirmação completa do tráfego depende também de #05/#06. Responsável pela preparação: Codex; responsável pela validação real: a definir.

**Passo a passo**
- [ ] Definir a máquina A como cliente e a máquina B como servidor; usar duas máquinas na mesma LAN ou VMs com rede adequada.
- [ ] Anotar IPv4 e adaptador de cada máquina com `ipconfig` no Windows (ou `ip addr` no Linux).
- [ ] Registrar IP_A, IP_B e o nome exato da interface que será capturada; documentar em `docs/topologia.md`.
- [ ] Testar A → B com `ping IP_B`; caso ICMP seja bloqueado, testar depois com a conexão TCP à porta 80.
- [ ] Verificar se TCP/80 e UDP/53 estão livres em B. No Windows, usar `netstat -ano` e consultar o PID caso haja conflito.
- [ ] Permitir somente o tráfego de teste necessário no firewall de B, preferencialmente na rede privada/laboratório, e desfazer as liberações ao final.

**Critérios de aceite**
- [ ] IP_A e IP_B estão registrados e há conectividade demonstrável.
- [ ] A pode alcançar B, e as portas pretendidas não estão ocupadas por outro serviço.
- [ ] A interface correta de captura foi identificada em B.

**Evidência esperada:** Print de `ipconfig`, topologia simples e teste de conectividade.

**Notas / PR / commit:** ______________________________________________

---

### ISSUE #03 — Desenvolver servidor HTTP em Python

**Área:** Desenvolvimento  
**Prioridade:** Crítica · **Dificuldade:** Média · **Esforço estimado:** 60–90 min  
**Dependências:** #01, #02 · **Responsável:** _a definir_ · **Prazo:** _a definir_  

**Objetivo:** Criar tráfego HTTP não criptografado na porta TCP/80, com GET, POST e respostas observáveis.

**Passo a passo**
- [x] Criar `src/server_http.py` usando Flask; definir rota `GET /` que retorne texto/JSON e código HTTP 200.
- [x] Definir rota `POST /echo` que receba JSON e devolva uma confirmação; registrar o método recebido no terminal.
- [ ] Executar em `host="0.0.0.0"`, `port=80`, com `debug=False`. Não usar HTTPS na demonstração.
- [ ] Confirmar que B está em LISTEN na porta 80; resolver conflitos com outros serviços ou permissões antes do teste.
- [ ] Acessar `http://IP_B/` a partir de A e testar a rota POST pelo cliente Python.
- [x] Registrar as respostas esperadas (código, corpo e cabeçalhos) no README.
- [x] Configurar CLI com `--host`/`--port`, padrão 127.0.0.1:8080 e suporte a TCP/80 (configuração testada sem bind em 80).
- [x] Validar JSON, mídia e limite de 16 KiB com erros 400/415/413 em JSON.
- [x] Implementar aplicação importável sem rede e testes automatizados com unittest.

**Critérios de aceite**
- [x] GET retorna HTTP 200 e POST retorna uma resposta consistente.
- [ ] A conexão funciona pela rede entre A e B usando TCP/80.
- [ ] Wireshark decodifica o protocolo como HTTP, sem TLS.

**Evidência esperada:** Terminal do servidor, resposta do cliente e captura com `http.request`.

**Notas / PR / commit:** Código e validação local concluídos em 23/11/2026 (America/Sao_Paulo), Windows, Python 3.12.10, Flask 3.1.3. `python -m unittest discover -s tests -v`: 14 testes aprovados na `.venv`. GET/POST reais em loopback 127.0.0.1:8080 retornaram 200 e os casos de erro retornaram 400/415/413; servidor encerrado ao final. Sintaxe, importações das cinco dependências, `pip check` e `git diff --check` verificados. README documenta instalação, Windows/Linux, CLI, rotas, erros e captura. Nenhum commit/push realizado.

**Status:** Issue #03 parcialmente concluída: implementação pronta; execução real em TCP/80, comunicação A ↔ B, decodificação no Wireshark e revisão pelo grupo permanecem pendentes. Linux não executado. Nenhuma captura, alteração de firewall, implementação DNS/cliente ou modificação do NetProbe realizada.

---

### ISSUE #04 — Desenvolver servidor DNS UDP em Python

**Área:** Desenvolvimento  
**Prioridade:** Crítica · **Dificuldade:** Média · **Esforço estimado:** 90–150 min  
**Dependências:** #01, #02 · **Responsável:** _a definir_ · **Prazo:** _a definir_  

**Objetivo:** Receber uma consulta DNS de A e responder em UDP/53, para capturar pergunta e resposta sem depender de DNS público.

**Passo a passo**
- [ ] Criar `src/server_dns.py` usando `socket` UDP e `dnslib` para interpretar mensagens DNS.
- [ ] Abrir um socket em `0.0.0.0:53` e processar mensagens com `DNSRecord.parse(...)`.
- [ ] Ao receber consulta tipo A para `demo.lab.`, montar resposta válida com o IPv4 de B; manter ID da transação.
- [ ] Para outros nomes/tipos, retornar resposta coerente (ex.: NXDOMAIN), sem encaminhar consultas para a internet.
- [ ] Registrar em console IP do cliente, nome consultado, tipo e resultado enviado.
- [ ] Testar a partir de A com `nslookup demo.lab IP_B` e confirmar pacotes UDP/53 no Wireshark.

**Critérios de aceite**
- [ ] Servidor inicia e responde na porta UDP/53 sem conflito.
- [ ] Há uma pergunta DNS e sua resposta com o mesmo Transaction ID.
- [ ] Consulta `demo.lab` retorna IP_B quando o tipo consultado é A.

**Evidência esperada:** Print do `nslookup`, terminal DNS e captura com `dns`.

**Notas / PR / commit:** ______________________________________________

---

### ISSUE #05 — Desenvolver o cliente de testes Python

**Área:** Desenvolvimento  
**Prioridade:** Crítica · **Dificuldade:** Média · **Esforço estimado:** 60–90 min  
**Dependências:** #03, #04 · **Responsável:** _a definir_ · **Prazo:** _a definir_  

**Objetivo:** Gerar, com um único comando, as transações HTTP e DNS necessárias à demonstração.

**Passo a passo**
- [ ] Criar `src/client.py` com configuração de `IP_B` por argumento ou constante claramente identificada.
- [ ] Enviar `GET http://IP_B/` e `POST http://IP_B/echo` por `requests` e mostrar status e conteúdo.
- [ ] Montar consulta DNS do tipo A para `demo.lab` com `dnslib`; enviar por socket UDP diretamente a `IP_B:53`.
- [ ] Aguardar a resposta DNS com timeout curto, decodificar e imprimir domínio, tipo e IP retornado.
- [ ] Gerar uma sequência curta, por exemplo 3 rodadas com pausa, para deixar os pacotes visíveis na captura.
- [ ] Tratar timeout, IP incorreto e serviço indisponível com mensagens claras; não testar automaticamente endereços externos.

**Critérios de aceite**
- [ ] Um comando provoca GET, POST e consulta DNS em B.
- [ ] Cliente imprime sucesso e erros sem travar indefinidamente.
- [ ] O Wireshark consegue correlacionar todas as operações ao IP_A.

**Evidência esperada:** Saída completa do cliente e demonstração de cada requisição na captura.

**Notas / PR / commit:** ______________________________________________

---

### ISSUE #06 — Preparar captura de pacotes ao vivo

**Área:** Captura e análise  
**Prioridade:** Crítica · **Dificuldade:** Baixa · **Esforço estimado:** 30–60 min  
**Dependências:** #02, #03, #04 · **Responsável:** _a definir_ · **Prazo:** _a definir_  

**Objetivo:** Observar o tráfego entre A e B na interface de B durante a execução do cliente.

**Passo a passo**
- [ ] Instalar Wireshark e driver de captura (Npcap no Windows) na máquina de monitoramento.
- [ ] Abrir Wireshark em B, selecionar a interface da LAN identificada na issue #02, não uma interface inativa.
- [ ] Iniciar captura sem filtro de captura, gerar uma requisição simples de A e confirmar que IP_A → IP_B aparece.
- [ ] Somente depois aplicar filtros de exibição; diferenciá-los de filtros de captura para não ocultar tráfego por engano.
- [ ] Verificar estatísticas da captura, inclusive indicação de pacotes descartados, quando fornecida pelo driver.
- [ ] Salvar uma captura pequena em `docs/evidencias/captura-demo.pcapng` sem coletar tráfego alheio.

**Critérios de aceite**
- [ ] Pacotes bidirecionais A ↔ B aparecem ao vivo.
- [ ] A interface selecionada está documentada.
- [ ] Não há descarte reportado durante o teste, se a plataforma fornecer essa métrica; registrar a limitação caso não forneça.

**Evidência esperada:** Print do Wireshark em captura ao vivo e arquivo `.pcapng` restrito ao laboratório.

**Notas / PR / commit:** ______________________________________________

---

### ISSUE #07 — Validar filtragem de tráfego HTTP

**Área:** Captura e análise  
**Prioridade:** Alta · **Dificuldade:** Baixa · **Esforço estimado:** 25–45 min  
**Dependências:** #03, #05, #06 · **Responsável:** _a definir_ · **Prazo:** _a definir_  

**Objetivo:** Isolar na captura o protocolo HTTP, suas requisições e respostas sobre TCP/80.

**Passo a passo**
- [ ] Iniciar a captura antes de executar o cliente; enviar GET e POST.
- [ ] Aplicar filtro de exibição `tcp.port == 80` para mostrar o fluxo TCP na porta exigida.
- [ ] Aplicar `http` e `http.request` para destacar as mensagens HTTP decodificadas.
- [ ] Selecionar a requisição GET, a POST e suas respostas; observar códigos e métodos.
- [ ] Confirmar IPs de origem/destino e o par de portas TCP; opcionalmente usar Follow TCP Stream.

**Critérios de aceite**
- [ ] Requisições GET/POST e respostas aparecem na captura.
- [ ] Tráfego está identificado na porta TCP/80.
- [ ] Existe screenshot com método, portas e endereços legíveis.

**Evidência esperada:** Captura de tela com filtro `http` e detalhes da requisição.

**Notas / PR / commit:** ______________________________________________

---

### ISSUE #08 — Validar filtragem de consultas DNS

**Área:** Captura e análise  
**Prioridade:** Alta · **Dificuldade:** Baixa · **Esforço estimado:** 25–45 min  
**Dependências:** #04, #05, #06 · **Responsável:** _a definir_ · **Prazo:** _a definir_  

**Objetivo:** Isolar e correlacionar perguntas e respostas DNS que usam UDP/53.

**Passo a passo**
- [ ] Iniciar a captura, executar a consulta para `demo.lab` diretamente ao IP_B.
- [ ] Aplicar filtro `udp.port == 53` e, em seguida, `dns` ou `dns && udp.port == 53`.
- [ ] Abrir detalhes da mensagem Query: localizar QNAME, QTYPE=A e identificador da transação.
- [ ] Abrir detalhes da resposta correspondente: conferir mesmo Transaction ID e registro A para IP_B.
- [ ] Anotar portas de origem efêmera do cliente e destino 53, e o sentido inverso na resposta.

**Critérios de aceite**
- [ ] Uma pergunta e uma resposta DNS estão visíveis.
- [ ] Nome de domínio, tipo A, identificador e resposta são verificáveis.
- [ ] Porta UDP/53 e os IPs de A/B aparecem corretamente.

**Evidência esperada:** Print mostrando query e response DNS e campos expandidos.

**Notas / PR / commit:** ______________________________________________

---

### ISSUE #09 — Inspecionar cabeçalhos IP e transporte

**Área:** Captura e análise  
**Prioridade:** Alta · **Dificuldade:** Baixa · **Esforço estimado:** 25–45 min  
**Dependências:** #07, #08 · **Responsável:** _a definir_ · **Prazo:** _a definir_  

**Objetivo:** Explicar a camada 3 (IP) e a camada 4 (TCP ou UDP) em pacotes reais.

**Passo a passo**
- [ ] Escolher um pacote HTTP e expandir `Internet Protocol Version 4` no Wireshark.
- [ ] Anotar `Source Address` e `Destination Address` e relacionar com IP_A e IP_B.
- [ ] Expandir `Transmission Control Protocol` e ler `Source Port` e `Destination Port`.
- [ ] Repetir com um pacote DNS e expandir `User Datagram Protocol`.
- [ ] Criar quadro comparativo pequeno: HTTP = TCP/80; DNS = UDP/53; porta de cliente normalmente efêmera.
- [ ] Confirmar que direção das respostas inverte origem/destino.

**Critérios de aceite**
- [ ] Grupo consegue apontar dois IPs e duas portas em HTTP e em DNS.
- [ ] Sabe distinguir TCP de UDP, sem confundir a porta efêmera com a porta do serviço.

**Evidência esperada:** Dois screenshots com campos de IPv4 e TCP/UDP expandidos.

**Notas / PR / commit:** ______________________________________________

---

### ISSUE #10 — Decodificar dados de aplicação

**Área:** Captura e análise  
**Prioridade:** Alta · **Dificuldade:** Baixa · **Esforço estimado:** 30–50 min  
**Dependências:** #07, #08 · **Responsável:** _a definir_ · **Prazo:** _a definir_  

**Objetivo:** Mostrar dados úteis da camada de aplicação e explicar seu significado.

**Passo a passo**
- [ ] No pacote HTTP, expandir Hypertext Transfer Protocol e localizar `GET /` ou `POST /echo`.
- [ ] Exibir o método, o caminho, o cabeçalho Host e o código de resposta do servidor.
- [ ] Se for POST, mostrar payload controlado simples (ex.: `{"teste":"redes"}`) sem dados pessoais.
- [ ] No pacote DNS, expandir Domain Name System e identificar `Queries → Name: demo.lab`.
- [ ] Expandir `Answers` para demonstrar o IPv4 resolvido.
- [ ] Explicar que HTTP em texto claro permite inspeção, enquanto HTTPS cifra a aplicação.

**Critérios de aceite**
- [ ] Métodos GET e POST são identificados na captura.
- [ ] Nome DNS consultado e endereço retornado são mostrados.
- [ ] É apresentada uma diferença correta entre conteúdo de aplicação e cabeçalhos IP/TCP/UDP.

**Evidência esperada:** Prints das seções HTTP e DNS expandidas.

**Notas / PR / commit:** ______________________________________________

---

### ISSUE #11 — Executar testes integrados e tratar falhas

**Área:** Qualidade  
**Prioridade:** Crítica · **Dificuldade:** Média · **Esforço estimado:** 60–90 min  
**Dependências:** #03–#10 · **Responsável:** _a definir_ · **Prazo:** _a definir_  

**Objetivo:** Repetir a demonstração completa sem depender de improviso e saber recuperar falhas comuns.

**Passo a passo**
- [ ] Seguir o roteiro do NetProbe no README e verificar ICMP, ARP, associação IP/MAC, status em tempo real e portas TCP.
- [x] Parar e reiniciar o serviço usado como porta de teste e confirmar o resultado a cada rodada.
- [ ] Verificar o comportamento com um IP sem equipamento e uma entrada inválida.
- [ ] Repetir o roteiro em outra máquina ou VM do grupo e registrar dificuldades.
- [x] Registrar os resultados da primeira rodada na matriz com data, responsável e evidência.
- [x] Conferir o contador de descartes da captura original.

**Critérios de aceite**
- [ ] Os cinco critérios do professor são cumpridos de ponta a ponta.
- [ ] Teste é reproduzível a partir do README.
- [ ] Problemas conhecidos e suas soluções estão documentados.

**Evidência esperada:** [Matriz de testes](docs/matriz-testes.md) e [captura ARP](docs/evidencias/teste-arp-wifi-evidencia.pcapng).

**Notas / PR / commit:** ______________________________________________

---

### ISSUE #12 — Documentar instalação e execução

**Área:** Documentação  
**Prioridade:** Alta · **Dificuldade:** Baixa · **Esforço estimado:** 45–75 min  
**Dependências:** #01–#11 · **Responsável:** _a definir_ · **Prazo:** _a definir_  

**Objetivo:** Permitir que outro membro configure e execute o projeto sem apoio dos autores.

**Passo a passo**
- [ ] Escrever no README objetivo, arquitetura A/B, dependências e versões do Python/Wireshark.
- [ ] Incluir instruções Windows para criar ambiente virtual e instalar dependências.
- [ ] Descrever ordem de inicialização: servidor HTTP, servidor DNS, captura, cliente.
- [ ] Documentar configuração IP_B, portas 80/TCP e 53/UDP e filtros Wireshark usados.
- [ ] Registrar problemas: porta ocupada, firewall, Npcap ausente, interface errada e uso acidental de HTTPS.
- [ ] Adicionar links relativos às evidências e orientar encerramento dos serviços após a demonstração.

**Critérios de aceite**
- [ ] Um integrante diferente executa o procedimento do zero.
- [ ] Todos os comandos necessários estão no README, sem depender de instruções orais.

**Evidência esperada:** README completo e breve revisão feita por colega.

**Notas / PR / commit:** ______________________________________________

---

### ISSUE #13 — Montar o roteiro da demonstração

**Área:** Apresentação  
**Prioridade:** Alta · **Dificuldade:** Baixa · **Esforço estimado:** 40–60 min  
**Dependências:** #11, #12 · **Responsável:** _a definir_ · **Prazo:** _a definir_  

**Objetivo:** Demonstrar os cinco itens de avaliação de maneira direta, com evidência visível.

**Passo a passo**
- [ ] Abrir os dois terminais de B (HTTP e DNS), cliente em A e Wireshark em B.
- [ ] Apresentar IP_A, IP_B, portas usadas e qual interface será capturada.
- [ ] Iniciar Wireshark; rodar o cliente e mostrar pacotes surgindo ao vivo.
- [ ] Aplicar `tcp.port == 80` / `http` e demonstrar GET/POST.
- [ ] Aplicar `dns && udp.port == 53` e demonstrar consulta/resposta.
- [ ] Expandir IPv4, TCP/UDP e dados da aplicação; apontar cada campo exigido.
- [ ] Fazer ensaio sem depender de slides e manter `.pcapng` como evidência de contingência; a demonstração principal continua ao vivo.

**Critérios de aceite**
- [ ] O roteiro passa explicitamente pelos cinco itens avaliados.
- [ ] Todos os integrantes entendem quando e o que devem mostrar.
- [ ] O ensaio cabe no tempo disponibilizado pelo professor.

**Evidência esperada:** Roteiro de apresentação e prints do ensaio.

**Notas / PR / commit:** ______________________________________________

---

### ISSUE #14 — Preparar a defesa técnica e distribuir falas

**Área:** Apresentação  
**Prioridade:** Alta · **Dificuldade:** Média · **Esforço estimado:** 60–90 min  
**Dependências:** #07–#13 · **Responsável:** _a definir_ · **Prazo:** _a definir_  

**Objetivo:** Garantir que todos os participantes saibam justificar o sistema e explicar os pacotes mostrados.

**Passo a passo**
- [ ] Distribuir entre os membros: infraestrutura, HTTP, DNS, análise de pacotes e testes (ajustar à quantidade de pessoas).
- [ ] Revisar o que são IP, porta, cliente/servidor, TCP, UDP, GET, POST, DNS query e DNS response.
- [ ] Ensaiar respostas: por que porta 80? por que DNS usa UDP/53 aqui? o que muda se usar HTTPS?
- [ ] Ensaiar como localizar IPs e portas, como distinguir request/response e por que a porta do cliente varia.
- [ ] Pedir que cada integrante explique ao menos uma captura real sem consultar anotações.
- [ ] Confirmar presença de todos na apresentação, incluindo conexão de vídeo para quem for remoto.

**Critérios de aceite**
- [ ] Todos conseguem explicar o componente pelo qual são responsáveis.
- [ ] Qualquer integrante consegue identificar ao menos um pacote HTTP e um DNS.
- [ ] Presença e sequência das participações foram combinadas.

**Evidência esperada:** Tabela de responsáveis preenchida e checklist de ensaio concluído.

**Notas / PR / commit:** ______________________________________________

---

## Comandos de referência (Windows)
```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
# No servidor B, em terminais separados:
.\.venv\Scripts\python.exe src\server_http.py
.\.venv\Scripts\python.exe src\server_dns.py
# No cliente A (com IP_B definido no script ou em argumento):
.\.venv\Scripts\python.exe src\client.py
# Diagnóstico rápido:
ipconfig
netstat -ano | findstr :80
netstat -ano | findstr :53
Test-NetConnection -ComputerName IP_B -Port 80
nslookup demo.lab IP_B
```

## Filtros do Wireshark
```text
tcp.port == 80
http
http.request
dns && udp.port == 53
ip.addr == IP_A && ip.addr == IP_B   # substituir pelos IPs reais
```

> **Atenção:** filtros acima são de **exibição**. A informação de perda na captura depende das estatísticas fornecidas pelo driver; não declarar “zero perdas” se não houver medição. Capturar no mesmo computador com `localhost` exige interface de loopback e não demonstra dois computadores reais.

## Matriz de validação final
| Critério do professor | Issues ligadas | Evidência mínima | Resultado |
|---|---|---|---|
| 1. Captura em tempo real | #02, #05, #06, #11 | Tráfego A ↔ B surgindo ao vivo no Wireshark | ☐ |
| 2. HTTP TCP/80 | #03, #05, #07 | GET, POST e respostas filtradas | ☐ |
| 3. DNS UDP/53 | #04, #05, #08 | Query/response de `demo.lab` | ☐ |
| 4. IPs e portas | #09 | IPv4 e TCP/UDP expandidos em dois pacotes | ☐ |
| 5. Payload de aplicação | #10 | Métodos HTTP e nome DNS no dissector | ☐ |

## Ordem do ensaio (siga a sequência)
- [ ] A e B na rede; IPs anotados.
- [ ] Iniciar HTTP e DNS em B.
- [ ] Iniciar Wireshark na interface correta.
- [ ] Rodar o cliente em A e observar pacotes chegando.
- [ ] Filtrar HTTP e abrir GET/POST.
- [ ] Filtrar DNS e abrir query/response.
- [ ] Apontar IPv4, TCP/UDP e payload de aplicação.
- [ ] Salvar evidências e conferir o indicador de perdas, se disponível.
- [ ] Encerrar serviços e remover liberações temporárias do firewall.

## Riscos conhecidos e recuperação
- **Porta 80 ou 53 ocupada:** identificar serviço conflitante; não desligar serviço essencial do sistema. Usar VM/laboratório se necessário.
- **Firewall bloqueando:** liberar apenas o necessário para o laboratório e reverter depois.
- **Nada aparece no Wireshark:** conferir interface, endereço IP, uso de loopback e execução do cliente.
- **HTTP aparece como TLS/HTTPS:** usar explicitamente `http://IP_B/` na porta 80.
- **DNS não aparece:** enviar consulta diretamente ao DNS de B, evitando cache, DoH e resolvedores externos.
- **Não há medição de perda:** registrar que o driver não informou o contador; usar teste controlado e captura íntegra sem alegar 0 perdas.

## Distribuição de responsabilidades (preencher na reunião)
| Integrante | Issues | Prazo combinado | Estado |
|---|---|---|---|
|  |  |  | ☐ |
|  |  |  | ☐ |
|  |  |  | ☐ |
|  |  |  | ☐ |
|  |  |  | ☐ |

**Definição de pronto:** issue só é concluída quando implementada, testada por alguém do grupo e acompanhada de evidência ou documentação no repositório.

