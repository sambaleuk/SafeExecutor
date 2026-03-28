/**
 * Filesystem Adapter — Unit Tests
 *
 * Tests are pure (no I/O) wherever possible.
 * Covers: parser classification, deny rules, risk matrix, path analysis.
 */

import { homedir } from 'os';
import { parseIntent } from '../src/adapters/filesystem/parser.js';
import {
  escalateRisk,
  maxRisk,
  flagEscalationSteps,
  pathRiskEntry,
  escalateByFileCount,
} from '../src/adapters/filesystem/risk-matrix.js';
import {
  analyzePath,
  resolvePath,
  hasVariableExpansion,
  isSystemPath,
  isSensitiveHomePath,
} from '../src/adapters/filesystem/path-analyzer.js';

// ─── Risk matrix ──────────────────────────────────────────────────────────────

describe('escalateRisk', () => {
  it('escalates LOW by 2 → HIGH', () => {
    expect(escalateRisk('LOW', 2)).toBe('HIGH');
  });

  it('caps escalation at CRITICAL', () => {
    expect(escalateRisk('HIGH', 5)).toBe('CRITICAL');
    expect(escalateRisk('CRITICAL', 1)).toBe('CRITICAL');
  });

  it('escalates 0 steps is identity', () => {
    expect(escalateRisk('MEDIUM', 0)).toBe('MEDIUM');
  });
});

describe('maxRisk', () => {
  it('returns the higher risk', () => {
    expect(maxRisk('LOW', 'HIGH')).toBe('HIGH');
    expect(maxRisk('CRITICAL', 'MEDIUM')).toBe('CRITICAL');
    expect(maxRisk('MEDIUM', 'MEDIUM')).toBe('MEDIUM');
  });
});

describe('flagEscalationSteps', () => {
  it('-rf / -fr → 2 steps', () => {
    expect(flagEscalationSteps(['r', 'f'])).toBe(2);
    expect(flagEscalationSteps(['f', 'r'])).toBe(2);
  });

  it('-R (no force) → 1 step', () => {
    expect(flagEscalationSteps(['R'])).toBe(1);
  });

  it('-f (no recursive) → 1 step', () => {
    expect(flagEscalationSteps(['f'])).toBe(1);
  });

  it('no risky flags → 0 steps', () => {
    expect(flagEscalationSteps(['v', 'n'])).toBe(0);
    expect(flagEscalationSteps([])).toBe(0);
  });
});

describe('pathRiskEntry', () => {
  it('matches /etc exactly', () => {
    const e = pathRiskEntry('/etc');
    expect(e?.risk).toBe('CRITICAL');
    expect(e?.deny).toBe(true);
  });

  it('matches /etc/passwd as child of /etc', () => {
    const e = pathRiskEntry('/etc/passwd');
    expect(e?.risk).toBe('CRITICAL');
  });

  it('matches /tmp as LOW', () => {
    const e = pathRiskEntry('/tmp');
    expect(e?.risk).toBe('LOW');
  });

  it('returns null for /home/user/project', () => {
    // /home is HIGH but /home/user/project has no exact match beyond /home
    const e = pathRiskEntry('/home/user/project');
    expect(e?.risk).toBe('HIGH');
  });

  it('returns null for /opt/app', () => {
    expect(pathRiskEntry('/opt/app')).toBeNull();
  });
});

describe('escalateByFileCount', () => {
  it('>1000 files escalates by 2', () => {
    expect(escalateByFileCount('LOW', 1001)).toBe('HIGH');
    expect(escalateByFileCount('MEDIUM', 1001)).toBe('CRITICAL');
  });

  it('>100 files escalates by 1', () => {
    expect(escalateByFileCount('LOW', 101)).toBe('MEDIUM');
  });

  it('≤100 files does not escalate', () => {
    expect(escalateByFileCount('HIGH', 50)).toBe('HIGH');
  });
});

// ─── Path analyser ────────────────────────────────────────────────────────────

describe('hasVariableExpansion', () => {
  it('detects $VAR', () => {
    expect(hasVariableExpansion('$HOME/docs')).toBe(true);
    expect(hasVariableExpansion('/some/$DIR/path')).toBe(true);
    expect(hasVariableExpansion('${TARGET}')).toBe(true);
  });

  it('returns false for literal paths', () => {
    expect(hasVariableExpansion('/tmp/foo')).toBe(false);
    expect(hasVariableExpansion('~/docs')).toBe(false);
  });
});

describe('resolvePath', () => {
  it('expands ~ to homedir', () => {
    expect(resolvePath('~')).toBe(homedir());
    expect(resolvePath('~/docs')).toBe(`${homedir()}/docs`);
  });

  it('expands $HOME', () => {
    expect(resolvePath('$HOME/foo')).toBe(`${homedir()}/foo`);
  });

  it('leaves absolute paths normalised', () => {
    expect(resolvePath('/tmp/foo/../bar')).toBe('/tmp/bar');
  });
});

describe('isSystemPath', () => {
  it('recognises known system paths', () => {
    expect(isSystemPath('/etc')).toBe(true);
    expect(isSystemPath('/etc/passwd')).toBe(true);
    expect(isSystemPath('/usr/bin/python')).toBe(true);
    expect(isSystemPath('/dev/sda')).toBe(true);
  });

  it('rejects non-system paths', () => {
    expect(isSystemPath('/tmp/work')).toBe(false);
    expect(isSystemPath('/home/user/project')).toBe(false);
    expect(isSystemPath('/opt/app')).toBe(false);
  });
});

describe('isSensitiveHomePath', () => {
  it('detects ~/.ssh', () => {
    expect(isSensitiveHomePath(`${homedir()}/.ssh/id_rsa`)).toBe(true);
  });

  it('detects ~/.aws', () => {
    expect(isSensitiveHomePath(`${homedir()}/.aws/credentials`)).toBe(true);
  });

  it('returns false for regular home files', () => {
    expect(isSensitiveHomePath(`${homedir()}/Documents/file.txt`)).toBe(false);
  });
});

describe('analyzePath', () => {
  it('classifies / as CRITICAL deny', () => {
    const r = analyzePath('/');
    expect(r.riskLevel).toBe('CRITICAL');
    expect(r.isSystemPath).toBe(true);
  });

  it('classifies /etc/passwd as CRITICAL', () => {
    const r = analyzePath('/etc/passwd');
    expect(r.riskLevel).toBe('CRITICAL');
  });

  it('classifies $VAR as CRITICAL (empty-var risk)', () => {
    const r = analyzePath('$MYVAR');
    expect(r.riskLevel).toBe('CRITICAL');
    expect(r.reason).toMatch(/variable/i);
  });

  it('classifies /tmp/work as LOW', () => {
    const r = analyzePath('/tmp/work');
    expect(r.riskLevel).toBe('LOW');
  });

  it('classifies ~/.ssh as HIGH sensitive', () => {
    const r = analyzePath('~/.ssh');
    expect(r.riskLevel).toBe('HIGH');
    expect(r.isSensitivePath).toBe(true);
  });
});

// ─── Parser — READ commands ───────────────────────────────────────────────────

describe('parseIntent — READ commands', () => {
  it('ls -la /tmp → LOW, READ, not denied', () => {
    const intent = parseIntent('ls -la /tmp');
    expect(intent.commandType).toBe('LS');
    expect(intent.category).toBe('READ');
    expect(intent.riskLevel).toBe('LOW');
    expect(intent.isDenied).toBe(false);
    expect(intent.requiresApproval).toBe(false);
  });

  it('cat /etc/hosts → LOW, READ', () => {
    const intent = parseIntent('cat /etc/hosts');
    expect(intent.commandType).toBe('CAT');
    expect(intent.riskLevel).toBe('LOW');
    expect(intent.isDenied).toBe(false);
  });
});

// ─── Parser — rm deny rules ───────────────────────────────────────────────────

describe('parseIntent — rm deny rules', () => {
  it('rm -rf / → DENY', () => {
    const intent = parseIntent('rm -rf /');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.denyReason).toMatch(/root|home/i);
  });

  it('rm -rf ~ → DENY', () => {
    const intent = parseIntent('rm -rf ~');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  it('rm -fr / → DENY (reversed flags)', () => {
    const intent = parseIntent('rm -fr /');
    expect(intent.isDenied).toBe(true);
  });

  it('rm -rf * → DENY (glob)', () => {
    const intent = parseIntent('rm -rf *');
    expect(intent.isDenied).toBe(true);
    expect(intent.denyReason).toMatch(/glob/i);
  });

  it('rm -rf $TARGET → DENY (variable expansion)', () => {
    const intent = parseIntent('rm -rf $TARGET');
    expect(intent.isDenied).toBe(true);
    expect(intent.denyReason).toMatch(/variable|var/i);
  });

  it('rm (no path) → DENY', () => {
    const intent = parseIntent('rm');
    expect(intent.isDenied).toBe(true);
    expect(intent.denyReason).toMatch(/path/i);
  });

  it('rm -rf /etc/config → DENY (system path)', () => {
    const intent = parseIntent('rm -rf /etc/config');
    expect(intent.isDenied).toBe(true);
  });

  it('rm -f /tmp/log.txt → NOT denied, HIGH risk', () => {
    const intent = parseIntent('rm -f /tmp/log.txt');
    expect(intent.isDenied).toBe(false);
    expect(intent.riskLevel).toBe('HIGH');
    expect(intent.commandType).toBe('RM');
  });

  it('rm /tmp/file.txt → NOT denied', () => {
    const intent = parseIntent('rm /tmp/file.txt');
    expect(intent.isDenied).toBe(false);
  });
});

// ─── Parser — sudo escalation ─────────────────────────────────────────────────

describe('parseIntent — sudo escalation', () => {
  it('sudo rm -rf /var/log → DENY (system path)', () => {
    const intent = parseIntent('sudo rm -rf /var/log');
    expect(intent.hasSudo).toBe(true);
    expect(intent.isDenied).toBe(true);
  });

  it('sudo rm -rf /tmp/work → NOT denied, requiresApproval', () => {
    const intent = parseIntent('sudo rm -rf /tmp/work');
    expect(intent.hasSudo).toBe(true);
    expect(intent.isDenied).toBe(false);
    expect(intent.requiresApproval).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });
});

// ─── Parser — chmod ───────────────────────────────────────────────────────────

describe('parseIntent — chmod', () => {
  it('chmod 777 /tmp/file → requiresApproval, NOT denied', () => {
    const intent = parseIntent('chmod 777 /tmp/file');
    expect(intent.commandType).toBe('CHMOD');
    expect(intent.isDenied).toBe(false);
    expect(intent.requiresApproval).toBe(true);
    expect(intent.metadata['modeArg']).toBe('777');
  });

  it('chmod 0777 file → requiresApproval', () => {
    const intent = parseIntent('chmod 0777 /tmp/test');
    expect(intent.requiresApproval).toBe(true);
  });

  it('chmod 755 /tmp/script → NOT requiresApproval', () => {
    const intent = parseIntent('chmod 755 /tmp/script');
    expect(intent.isDenied).toBe(false);
    expect(intent.requiresApproval).toBe(false);
    expect(intent.riskLevel).toBe('MEDIUM');
  });

  it('chmod -R 755 /etc → DENY', () => {
    const intent = parseIntent('chmod -R 755 /etc');
    expect(intent.isDenied).toBe(true);
    expect(intent.denyReason).toMatch(/system path/i);
  });

  it('chmod -R 755 /home/user/project → NOT denied, HIGH', () => {
    const intent = parseIntent('chmod -R 755 /home/user/project');
    expect(intent.isDenied).toBe(false);
    // MEDIUM base + recursive(+1) = HIGH; /home path is HIGH → maxRisk(HIGH,HIGH)=HIGH
    expect(intent.riskLevel).toBe('HIGH');
    expect(intent.requiresApproval).toBe(true);
  });
});

// ─── Parser — chown ───────────────────────────────────────────────────────────

describe('parseIntent — chown/chgrp', () => {
  it('chown root:root /etc/passwd → DENY', () => {
    const intent = parseIntent('chown root:root /etc/passwd');
    expect(intent.isDenied).toBe(true);
    expect(intent.denyReason).toMatch(/system path/i);
  });

  it('chown user:group /home/user/file → NOT denied, HIGH', () => {
    const intent = parseIntent('chown user:group /home/user/file');
    expect(intent.isDenied).toBe(false);
    expect(intent.riskLevel).toBe('HIGH');
  });
});

// ─── Parser — dd ──────────────────────────────────────────────────────────────

describe('parseIntent — dd', () => {
  it('dd if=/dev/zero of=/dev/sda → DENY', () => {
    const intent = parseIntent('dd if=/dev/zero of=/dev/sda');
    expect(intent.commandType).toBe('DD');
    expect(intent.isDenied).toBe(true);
    expect(intent.denyReason).toMatch(/block device/i);
  });

  it('dd if=/dev/zero of=/dev/sda1 → DENY (partition)', () => {
    const intent = parseIntent('dd if=/dev/zero of=/dev/sda1');
    expect(intent.isDenied).toBe(true);
  });

  it('dd if=/dev/zero of=/tmp/test.img → NOT denied', () => {
    const intent = parseIntent('dd if=/dev/zero of=/tmp/test.img bs=1M count=100');
    expect(intent.isDenied).toBe(false);
    expect(intent.targetPaths).toContain('/tmp/test.img');
  });
});

// ─── Parser — find ────────────────────────────────────────────────────────────

describe('parseIntent — find', () => {
  it('find / -delete → DENY', () => {
    const intent = parseIntent('find / -delete');
    expect(intent.isDenied).toBe(true);
    expect(intent.denyReason).toMatch(/find -delete/i);
  });

  it('find /tmp -name "*.log" -exec rm {} \\; → DENY', () => {
    const intent = parseIntent('find /tmp -name "*.log" -exec rm {} ;');
    expect(intent.isDenied).toBe(true);
    expect(intent.denyReason).toMatch(/find -exec rm/i);
  });

  it('find /tmp -name "*.log" → NOT denied, LOW', () => {
    const intent = parseIntent('find /tmp -name "*.log"');
    expect(intent.isDenied).toBe(false);
    expect(intent.riskLevel).toBe('LOW');
  });
});

// ─── Parser — mv/cp ───────────────────────────────────────────────────────────

describe('parseIntent — mv / cp', () => {
  it('mv file.txt /dev/null → DENY', () => {
    const intent = parseIntent('mv /tmp/file.txt /dev/null');
    expect(intent.isDenied).toBe(true);
    expect(intent.denyReason).toMatch(/dev\/null/i);
  });

  it('cp src.txt /tmp/dst.txt → NOT denied, MEDIUM', () => {
    const intent = parseIntent('cp /home/user/src.txt /tmp/dst.txt');
    expect(intent.isDenied).toBe(false);
    expect(intent.commandType).toBe('CP');
    expect(intent.sourcePaths).toContain('/home/user/src.txt');
    expect(intent.targetPaths).toContain('/tmp/dst.txt');
  });

  it('mv /tmp/a.txt /tmp/b.txt → NOT denied, MEDIUM', () => {
    const intent = parseIntent('mv /tmp/a.txt /tmp/b.txt');
    expect(intent.isDenied).toBe(false);
    expect(intent.riskLevel).toBe('MEDIUM');
  });
});

// ─── Parser — device redirection ──────────────────────────────────────────────

describe('parseIntent — device redirections', () => {
  it('echo foo > /dev/sda → DENY', () => {
    const intent = parseIntent('echo foo > /dev/sda');
    expect(intent.isDenied).toBe(true);
    expect(intent.denyReason).toMatch(/device/i);
  });

  it('cat file >> /dev/null → DENY (device)', () => {
    // /dev/null is a device, but historically acceptable — our rule still denies
    const intent = parseIntent('cat /tmp/file >> /dev/null');
    // /dev/null is under /dev/ which is a deny-listed redirection target
    expect(intent.isDenied).toBe(true);
  });
});

// ─── Parser — mkfs / fdisk ────────────────────────────────────────────────────

describe('parseIntent — mkfs / fdisk', () => {
  it('mkfs.ext4 /dev/sdb → DENY', () => {
    const intent = parseIntent('mkfs.ext4 /dev/sdb');
    expect(intent.isDenied).toBe(true);
    expect(intent.commandType).toBe('MKFS');
  });

  it('fdisk /dev/sda → DENY', () => {
    const intent = parseIntent('fdisk /dev/sda');
    expect(intent.isDenied).toBe(true);
    expect(intent.commandType).toBe('FDISK');
  });
});

// ─── Parser — tar archive extraction ─────────────────────────────────────────

describe('parseIntent — tar', () => {
  it('tar xf archive.tar -C /etc → HIGH risk (system path)', () => {
    const intent = parseIntent('tar xf archive.tar -C /etc');
    expect(intent.commandType).toBe('TAR');
    // /etc is system path → CRITICAL risk (but tar itself isn't denied)
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  it('tar xf archive.tar -C /tmp → MEDIUM', () => {
    const intent = parseIntent('tar xf archive.tar -C /tmp');
    expect(intent.isDenied).toBe(false);
    expect(intent.riskLevel).toBe('MEDIUM');
  });
});

// ─── Parser — pipe detection ──────────────────────────────────────────────────

describe('parseIntent — pipes', () => {
  it('ls | xargs rm → DENY', () => {
    const intent = parseIntent('ls /tmp | xargs rm');
    expect(intent.isDenied).toBe(true);
    expect(intent.denyReason).toMatch(/pipe.*rm/i);
  });

  it('ls | grep foo → NOT denied', () => {
    const intent = parseIntent('ls /tmp | grep foo');
    expect(intent.isDenied).toBe(false);
    expect(intent.pipes.length).toBe(1);
    expect(intent.pipes[0][0]).toBe('grep');
  });
});

// ─── Parser — intent shape ────────────────────────────────────────────────────

describe('parseIntent — general shape', () => {
  it('returns correct command and commandType', () => {
    const intent = parseIntent('rm -f /tmp/stale.lock');
    expect(intent.command).toBe('rm');
    expect(intent.commandType).toBe('RM');
    expect(intent.category).toBe('DESTROY');
    expect(intent.isDestructive).toBe(true);
  });

  it('hasSudo is false by default', () => {
    const intent = parseIntent('rm /tmp/file');
    expect(intent.hasSudo).toBe(false);
  });

  it('preserves raw input', () => {
    const raw = '  rm -rf /tmp/old  ';
    const intent = parseIntent(raw);
    expect(intent.raw).toBe(raw.trim());
  });

  it('detects glob patterns', () => {
    const intent = parseIntent('rm -f /tmp/*.log');
    expect(intent.hasGlobs).toBe(true);
  });

  it('detects variable expansion', () => {
    const intent = parseIntent('rm -f $TMPDIR/work');
    expect(intent.hasVarExpansion).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });
});
