# Laboratório ARM64 KASAN — Moto G200 (somente nuvem)

## Objetivo

Compilar **um kernel público Android 12 / Linux 5.4.147** com KASAN genérico no runner ARM64 do GitHub Actions, inicializá-lo no QEMU com um initramfs mínimo e preservar logs de verificação. A compilação **não é** o kernel binário Motorola: trata-se de uma *base de referência* fixada no commit `34b5f809f17e66d5011086a3d90802989e667f75` (`android12-5.4.147_r00`). Correspondência com as funções do firmware Motorola ainda está **pendente**.

O pacote **não contém** `boot_a.img`, ramdisk, firmware, Magisk, dados pessoais, chaves, segredos, exploits ou gatilhos GhostLock.

## Como executar no GitHub pelo navegador do telefone

1. Crie um repositório GitHub para este projeto (público se quiser runners ARM64 gratuitos sem consumir minutos do plano; **nenhuma informação privada deve ser publicada**). Repositórios privados consomem a cota de minutos da conta.
2. Envie a **estrutura de pastas** do pacote, preservando `.github/workflows/arm64-kasan-lab.yml` e as pastas `scripts/` e `initramfs/`. Não faça upload do ZIP como arquivo único dentro do repositório: o Actions precisa enxergar os arquivos descompactados.
3. Em **Actions**, escolha **Moto G200 - KASAN ARM64 (laboratorio isolado)** e pressione **Run workflow**.
4. Ao terminar, leia o status do job e baixe o artefato **kasan-arm64-lab-evidencias** contendo logs de compilação/execução e resumo. O primeiro teste pode falhar por incompatibilidade de fontes/compilador: nesse caso, consulte o log e pare; **nenhuma correção automática é aplicada**.

## Etapas e evidências

- `scripts/preflight.sh` recusa nomes suspeitos de arquivos privados e impede que esses arquivos sejam adicionados ao laboratório.
- CI é **somente acionamento manual**, com `permissions: contents: read` e sem secrets.
- Runner `ubuntu-24.04-arm` (ARM64 hospedado; nenhuma tarefa roda no Moto G200).
- Fonte pública Android Common `android12-5.4.147_r00` fixada em SHA de commit.
- ARM64 `defconfig` adaptado para QEMU `virt` e KASAN genérico com `KASAN_OUTLINE`.
- `make Image`, verificação de configurações e de símbolos KASAN, initramfs C pequeno, QEMU TCG.
- Requer marcador `KASAN_LAB_INIT_OK` na saída serial e ausência de pânico do kernel.
- Resultados em `reports/`, publicados por 7 dias. Sem upload de boot, kernel Image ou vmlinux.

## Limitações e precauções

- A imagem Motorola permanece **somente** na área de análise local privada; nada aqui busca ou lê esse arquivo.
- A compilação baseada no Android Common **não garante equivalência** com Motorola/Qualcomm nem confirma a CVE-2026-43499 ou root.
- Testes KASAN de falha induzida e caminhos GhostLock **não estão habilitados**; o primeiro objetivo é comprovar compilação e inicialização do kernel instrumentado em isolamento.
- KASAN consome memória e CPU; o QEMU usa 2 GiB, 2 CPUs e timeout de 240 segundos. Há limites de 2 horas para o job.
- 14 GB de disco do runner podem ser insuficientes em alguns cenários. Este pipeline desabilita geração de DWARF para a primeira inicialização.
- A ausência do marcador de inicialização **não é PASS**; o job falhará com logs consultáveis.
- Se compilar mas não inicializar, revisar configuração e drivers virtuais no laboratório. Nunca experimentar essas imagens no aparelho.

## Arquivos de auditoria no artefato

`preflight.txt`, `toolchain-and-source.txt`, `source-files-sha256.txt`, `kasan-config.txt`, `kernel-build.txt`, `qemu-serial.log`, `qemu-result.txt`, `status.txt`.

## Fontes

- https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- https://android.googlesource.com/kernel/common/+/refs/tags/android12-5.4.147_r00
- https://docs.kernel.org/5.17/dev-tools/kasan.html

## Checklist de sucesso

- [ ] Commit da fonte pública confere com SHA fixado.
- [ ] `CONFIG_KASAN=y`, `CONFIG_KASAN_GENERIC=y`, `CONFIG_KASAN_OUTLINE=y` presentes no `.config` final.
- [ ] Compilação ARM64 `Image` concluída e símbolos de instrumentação encontrados.
- [ ] QEMU inicializa e `KASAN_LAB_INIT_OK` aparece no log serial.
- [ ] Telefone não recebe nenhuma instalação, flashing, exploração ou comando ADB.

**Status atual deste pacote**: arquivos preparados e validação local de sintaxe; a compilação/execução no GitHub depende do upload e da execução do workflow na conta do usuário. Não declarar PASS antecipadamente.

## Validacao segura na pasta do Moto G200 (sem compilar kernel)
O diretorio local e /storage/emulated/0/Estudo/laboratorio/moto-g200-kasan-ci.
Executar: bash scripts/verify-local.sh, dentro da pasta do projeto.
O script nao executa Futex, GhostLock, QEMU nem compila o kernel do aparelho.
Os testes de compilacao do Linux ARM64 e inicializacao no QEMU exigem um
repositorio GitHub acessivel e a execucao manual do GitHub Actions.
Em caso de falha do build no runner, consultar reports/kernel-build.log.

## Primeira execucao remota
O workflow executa ao receber o primeiro commit que publica o arquivo
.github/workflows/arm64-kasan-lab.yml na branch main.
Tambem pode ser acionado manualmente pela aba Actions.
Nunca enviar boot_a.img. O processamento ARM64+QEMU ocorre apenas na nuvem.
