# Issue #11 — Matriz de testes do NetProbe Wi-Fi

- **Data de execução** — 24/11/2026
- **Responsável** — João Pedro Mendes

## Comandos gerais

Nas duas máquinas, consultamos IPv4, máscara e gateway:

```
ipconfig
```

Comparamos os valores do adaptador **Wi-Fi** das duas máquinas para confirmar a sub-rede usada no teste.

| Máquina | Função | IPv4 | Máscara | Gateway IPv4 |
| --- | --- | --- | --- | --- |
| A — PC principal | Executou o NetProbe e o Wireshark | `192.168.1.10` | `255.255.255.0` | `192.168.1.1` |
| B — notebook | Equipamento de teste | `192.168.1.4` | `255.255.255.0` | `192.168.1.1` |

Os valores confirmaram que A e B estavam configuradas na sub-rede `192.168.1.0/24`.

No PowerShell do PC principal, na pasta do projeto, iniciamos o NetProbe:

```
& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" tools/netprobe.py
```

Quando o programa pediu os valores, informamos a rede 192.168.1.0/24.
Pressionar Enter no campo de timeout selecionou 0.5 s. As portas inicial
e final foram informadas conforme cada teste.

## Matriz de resultados

| Teste | Esperado | Observado | Status | Observação |
| --- | --- | --- | --- | --- |
| 01 — ICMP | Notebook aparece como Online (ICMP) | Ping do Windows recebeu 4 de 4 respostas. O NetProbe mostrou 192.168.1.4 como Online (ICMP) | Passou | Permitimos temporariamente que o PC principal enviasse ping ao notebook. A regra foi removida após o teste. |
| 02 — ARP | Notebook é encontrado mesmo sem resposta ao ping | Ping sem resposta no pacote 1, seguido da requisição ARP 2 e da resposta ARP 3 da evidência. O NetProbe mostrou o notebook online por ARP | Passou | Instalamos o Npcap no PC principal e capturamos na interface Wi-Fi com o Wireshark. |
| 03 — IP/MAC | MAC da tabela corresponde ao Wi-Fi do notebook | 192.168.1.4 apareceu com E4:FD:45:2F:9E:7D, igual ao ipconfig /all e à resposta ARP | Passou | Comparamos o adaptador Wi-Fi do notebook com a tabela e a captura. |
| 04 — Porta TCP e reinício | Porta 8000 aparece, some ao parar o servidor e volta após reiniciar | No intervalo 7999–8001, a sequência foi 8000, Nenhuma detectada e 8000. O notebook continuou online | Passou | Usamos o servidor HTTP do Python no notebook e confirmamos que a porta estava acessível antes da varredura. |
| 05 — Intervalo de portas | A porta aberta 8000 fica fora do resultado quando só a 8001 é consultada | O NetProbe mostrou Nenhuma detectada | Passou | O servidor permaneceu ligado na porta 8000. |
| 06 — Timeout configurável | A varredura conclui com um timeout diferente do padrão | Com 0.2 s, a varredura da /24 terminou e encontrou o notebook por ARP | Passou | A execução pareceu mais rápida que a de 0.5 s. A duração não foi cronometrada. |
| 07 — Interface em tempo real | Estados online e sem resposta aparecem durante a varredura | O terminal mostrou as etapas e, só no fim, a tabela com os dispositivos detectados | Falhou | Retestar a interface após a correção, com o notebook ligado e um IP conhecido sem equipamento. |

## Comandos específicos

### 01 — Descoberta por ICMP

No PowerShell como administrador do notebook, criamos a regra temporária:

```
New-NetFirewallRule -Name "NetProbeTestePing" -DisplayName "NetProbe - teste de ping" -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -RemoteAddress 192.168.1.10
```

No PC principal, verificamos o ping:

```
ping 192.168.1.4
```

O notebook respondeu aos quatro pings, com 0% de perda. Depois, rodamos o
NetProbe com timeout de `0.5 s` e portas `80–80`. O programa mostrou
`192.168.1.4` como `Online (ICMP)`.

Após a rodada, removemos a regra no PowerShell como administrador do notebook:

```
Remove-NetFirewallRule -Name "NetProbeTestePing"
```

Na rodada seguinte, o notebook voltou a aparecer como online por ARP.

### 02 — Descoberta por ARP

No PowerShell do PC principal, verificamos o estado do driver:

```
sc.exe query npcap
```

O Windows mostrou o driver como `RUNNING`.

Capturamos na interface Wi-Fi do Wireshark durante a execução do NetProbe,
com timeout de 0.5 s e portas 80–80. Depois, aplicamos os filtros de exibição
abaixo, um por vez.

```
icmp && ip.addr == 192.168.1.10 && ip.addr == 192.168.1.4
```

Mostra pacotes ICMP entre A e B nos dois sentidos. O pacote **1** da evidência foi uma
solicitação de ping de A para B sem resposta correspondente na captura.

```
arp && ((arp.src.proto_ipv4 == 192.168.1.10 && arp.dst.proto_ipv4 == 192.168.1.4) || (arp.src.proto_ipv4 == 192.168.1.4 && arp.dst.proto_ipv4 == 192.168.1.10))
```

Mostra mensagens ARP entre os dois endereços nos dois sentidos. Depois do ping,
A perguntou pelo IP de B no pacote **2** e B informou seu MAC no pacote
**3**. O NetProbe listou B como online por ARP.

**Evidência** — [Captura do teste ARP](evidencias/teste-arp-wifi-evidencia.pcapng).
A evidência contém três pacotes exportados da captura original.

| Pacote na evidência | Pacote original | O que mostra |
| --- | --- | --- |
| 1 | 392 | Ping sem resposta na captura original |
| 2 | 1108 | Requisição ARP do PC |
| 3 | 1109 | Resposta ARP do notebook |

**Descartes na captura original** — o Wireshark reportou **0 (0,0%)** na interface
Wi-Fi, com **2.838 pacotes** capturados em **3 min 02 s**. A coleta foi feita
sem filtro de captura. O arquivo inclui tráfego além do cenário entre A e B.

### 03 — Associação IP/MAC

No Prompt de Comando do notebook, conferimos o endereço físico do Wi-Fi:

```
ipconfig /all
```

O adaptador Wi-Fi de B mostrou `192.168.1.4` e o endereço físico
`E4-FD-45-2F-9E-7D`.

No PowerShell do PC principal, conferimos a associação registrada pelo Windows:

```
arp -a 192.168.1.4
```

A tabela ARP do Windows mostrou uma entrada dinâmica com o mesmo IP e MAC.
Os mesmos valores apareceram na tabela do NetProbe e na resposta ARP capturada.

### 04 e 05 — Porta TCP e intervalo

No Prompt de Comando do notebook, criamos uma pasta vazia e iniciamos o servidor:

```
mkdir "%TEMP%\netprobe-teste"
python -m http.server 8000 --bind 192.168.1.4 --directory "%TEMP%\netprobe-teste"
```

No PowerShell do PC principal, verificamos se a porta estava acessível:

```
Test-NetConnection 192.168.1.4 -Port 8000
```

O resultado foi TcpTestSucceeded : True.

No teste 04, como definimos a porta 8000 para o servidor, usamos o intervalo
7999–8001. Rodamos o NetProbe com o servidor ligado, depois de pará-lo com
Ctrl+C e novamente após reiniciá-lo com o mesmo comando.
O notebook continuou online nas três rodadas. A coluna de portas mostrou
`8000`, depois `Nenhuma detectada` e, após o reinício, `8000` novamente.

No teste 05, mantivemos o servidor na porta 8000 e usamos 8001 nos dois campos
de porta do NetProbe.
O notebook continuou online e a coluna mostrou `Nenhuma detectada`.

### 06 e 07 — Timeout e interface

No teste 06, informamos `0.2` no campo de timeout e `8000` nos dois campos de
porta. A varredura terminou e listou B como online por ARP com o MAC esperado.
A duração das rodadas com `0.2 s` e `0.5 s` ficou sem medição.

No teste 07, observamos a saída durante a varredura. O terminal indicou as
etapas em andamento e mostrou os resultados por IP apenas na tabela final.
A tabela também omitiu os IPs sem resposta. Por isso, o teste da interface
em tempo real falhou.

### 07 — Reteste da interface no hotspot

Em 25/11/2026, João Pedro Mendes repetiu o teste com a versão `e3045f9`.
O PC A usou `10.103.91.147` e o notebook B usou `10.103.91.115`.
Todas as rodadas usaram `10.103.91.0/24`, timeout de `0.5 s` e intervalo
de portas `8000–8000`.

| Cenário | Resultado no Passo 2 para `10.103.91.115` | Status |
| --- | --- | --- |
| B conectado | `Online (ARP - Firewall Detectado)` com MAC `f6-55-b8-e3-50-3d` | Passou |
| B desconectado, com entrada dinâmica ainda no cache ARP de A | Mesmo status online e mesmo MAC | Falhou |
| B desconectado, após remover a entrada de B do cache ARP de A | `Offline (sem resposta)` | Passou com o cache limpo |

O NetProbe pode usar um MAC antigo do cache como sinal de que o dispositivo
está online. Nesta rodada, a consulta `arp -a 10.103.91.115 -N 10.103.91.147`
mostrou a entrada dinâmica. No PowerShell como administrador de A, usamos
`arp -d 10.103.91.115 10.103.91.147` e repetimos a consulta para confirmar
que a entrada tinha sumido antes de rodar o NetProbe novamente.

Evidência desta rodada registrada pelo operador durante o teste. O print
do terminal ainda precisa ser anexado.

### 07 — Reteste após a correção no Wi-Fi normal

Em 25/11/2026, João Pedro Mendes repetiu o teste com a versão local que
seleciona a interface ARP pela rota do destino e usa o cache apenas para
preencher o MAC de um IP que respondeu ao ICMP. O PC A usou `192.168.1.10`
e o notebook B usou `192.168.1.4`. A rede foi `192.168.1.0/24`, com
timeout de `0.5 s` e portas `8000–8000`.

| Cenário | Resultado no Passo 2 | Status |
| --- | --- | --- |
| B conectado | `Online (ARP)` com o MAC esperado do notebook | Passou |
| Wi-Fi de B desligado, com o MAC ainda no cache ARP de A | `Offline (sem resposta)` | Passou |

Resultados informados pelo operador. A entrada ARP foi consultada antes
da segunda rodada e permaneceu no cache sem limpeza manual.

## Pendências para fechar a Issue #11

- Anexar a evidência do terminal do reteste no Wi-Fi normal. O hotspot
  fica registrado como diagnóstico, sem nova rodada prevista.
- Cronometrar a varredura completa da `/24` e verificar a mensagem para uma
  entrada inválida.
- Em 26/11/2026, executar a bateria completa com os notebooks que serão
  usados na apresentação e confirmar os cinco critérios na versão escolhida.
  Pedir a outro integrante que siga o roteiro do README e registrar os
  resultados, as dificuldades e suas soluções.
