export function bashCompletion(): string {
  return `# zks bash completion
_zks() {
  local cur prev opts
  COMPREPLY=()
  cur="\${COMP_WORDS[COMP_CWORD]}"
  prev="\${COMP_WORDS[COMP_CWORD-1]}"
  opts="init validate plan apply rotate run inventory where auth audit config trust capture doctor completions help"
  case "\${COMP_WORDS[1]}" in
    init) opts="--policy --project --detect" ;;
    validate) opts="--policy" ;;
    plan) opts="--policy --only --target" ;;
    apply) opts="--policy --only --target --agent" ;;
    rotate) opts="--target --check --policy" ;;
    run) opts="--policy --only --agent" ;;
    inventory) opts="--policy --project --older-than" ;;
    where) opts="--policy" ;;
    auth) opts="status set delete" ;;
    audit) opts="list verify sync" ;;
    config) opts="show set unset" ;;
    trust) opts="list remove" ;;
    capture) opts="read fill login recipes clipboard file" ;;
    completions) opts="bash zsh fish" ;;
  esac
  if [[ \${cur} == -* ]]; then
    COMPREPLY=( $(compgen -W "\${opts}" -- \${cur}) )
    return 0
  fi
  COMPREPLY=( $(compgen -W "\${opts}" -- \${cur}) )
}
complete -F _zks zks
`;
}

export function zshCompletion(): string {
  return `#compdef zks
_zks() {
  local -a commands
  commands=(
    'init:Create a zks.policy.json template'
    'validate:Check the policy'
    'plan:List writes apply would make'
    'apply:Write values to providers'
    'rotate:Write a new value'
    'run:Run a command with secrets as env'
    'inventory:Show variable inventory'
    'where:Find files naming a variable'
    'auth:Manage provider tokens'
    'audit:Audit log operations'
    'config:Configuration'
    'trust:Manage trusted destinations'
    'capture:Capture secrets from browser'
    'doctor:Check tools and tokens'
    'completions:Generate shell completions'
    'help:Show help'
  )
  _describe 'command' commands
}
compdef _zks zks
`;
}

export function fishCompletion(): string {
  return `# zks fish completion
complete -c zks -f
complete -c zks -n '__fish_use_subcommand' -a 'init validate plan apply rotate run inventory where auth audit config trust capture doctor completions help'
complete -c zks -n '__fish_seen_subcommand_from init' -l policy -l project -l detect
complete -c zks -n '__fish_seen_subcommand_from validate' -l policy
complete -c zks -n '__fish_seen_subcommand_from plan' -l policy -l only -l target
complete -c zks -n '__fish_seen_subcommand_from apply' -l policy -l only -l target -l agent
complete -c zks -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish'
`;
}
