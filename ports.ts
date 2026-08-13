/**
 * العقود (Ports)
 *
 * الملف ده بيوصف **الوظيفة** المطلوبة، مش الأداة.
 * تشبيه: خطة المدرّب بتقول "قِس النبض"، مش "استخدم جهاز ماركة كذا".
 *
 * وده اللي خلّى نقلة المشروع من Node إلى كلاودفلير رخيصة:
 * العقد اتغيّر في سطرين بس (التوكنات بقت async لأن Web Crypto async)،
 * وكل المنطق فوقه فضل زي ما هو.
 */

import type { PermissionKey } from '../domain/permissions';

export type RoleKey = 'SUPER_ADMIN' | 'BRANCH_MANAGER' | 'STAFF';

export interface AuthenticatedUser {
  id: string;
  username: string;
  fullName: string;
  roleKey: RoleKey;
  branchId: string | null;
  permissions: PermissionKey[];
  mustChangePassword: boolean;
}

/** محتوى بطاقة الدخول. خفيف عمداً — بتتحمل مع كل طلب. */
export interface AccessTokenPayload {
  sub: string; // معرّف المستخدم
  sid: string; // معرّف الجلسة
  role: RoleKey;
  branchId: string | null;
  perms: string[];
  ver: number;
}

export interface PasswordHasher {
  hash(plain: string): Promise<string>;
  verify(stored: string, plain: string): Promise<boolean>;
  needsRehash(stored: string): boolean;
}

export interface TokenService {
  signAccessToken(payload: AccessTokenPayload, ttlSeconds: number, secret: string): Promise<string>;
  verifyAccessToken(token: string, secret: string): Promise<AccessTokenPayload>;
  createRefreshToken(): Promise<{ raw: string; digest: string }>;
  digestRefreshToken(raw: string): Promise<string>;
}

export interface Clock {
  now(): Date;
}

export interface AuditLogger {
  record(entry: {
    actorId?: string | null;
    action: string;
    entity?: string;
    entityId?: string;
    metadata?: Record<string, unknown>;
    ipAddress?: string | null;
    userAgent?: string | null;
  }): Promise<void>;
}

export interface RateLimiter {
  /** بترجع الثواني المتبقية لو محظور، أو null لو مسموح */
  check(key: string, limit: number, windowSeconds: number): Promise<number | null>;
  reset(key: string): Promise<void>;
}

export interface UserRecord {
  id: string;
  username: string;
  fullName: string;
  passwordHash: string;
  adminPasskeyHash: string | null;
  isActive: boolean;
  mustChangePassword: boolean;
  failedLoginCount: number;
  lockedUntil: Date | null;
  deletedAt: Date | null;
  branchId: string | null;
  roleKey: RoleKey;
  permissions: PermissionKey[];
}

export interface UserRepository {
  findByUsername(username: string): Promise<UserRecord | null>;
  findById(id: string): Promise<UserRecord | null>;
  registerFailedLogin(userId: string, lockUntil: Date | null): Promise<void>;
  clearLoginFailures(userId: string, loginAt: Date): Promise<void>;
  updatePasswordHash(userId: string, hash: string): Promise<void>;
}

export interface SessionRecord {
  id: string;
  userId: string;
  lastSeenAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
}

export interface SessionRepository {
  create(data: {
    userId: string;
    refreshTokenHash: string;
    expiresAt: Date;
    ipAddress?: string | null;
    userAgent?: string | null;
  }): Promise<SessionRecord>;
  findActiveByDigest(digest: string): Promise<SessionRecord | null>;
  findActiveById(id: string): Promise<SessionRecord | null>;
  touch(id: string, at: Date): Promise<void>;
  rotate(id: string, newDigest: string, at: Date): Promise<void>;
  revoke(id: string, reason: string, at: Date): Promise<void>;
  revokeAllForUser(userId: string, reason: string, at: Date): Promise<void>;
}

export interface AnnouncementRecord {
  id: string;
  title: string;
  body: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  isMandatory: boolean;
  createdAt: Date;
}

export interface AnnouncementRepository {
  findPendingFor(user: AuthenticatedUser, now: Date): Promise<AnnouncementRecord[]>;
  acknowledge(announcementId: string, userId: string, at: Date): Promise<void>;
  create(data: {
    title: string;
    body: string;
    severity: 'INFO' | 'WARNING' | 'CRITICAL';
    audience: 'ALL' | 'MANAGERS_ONLY' | 'STAFF_ONLY' | 'SINGLE_BRANCH';
    branchId: string | null;
    isMandatory: boolean;
    startsAt: Date;
    endsAt: Date | null;
    createdById: string;
  }): Promise<{ id: string }>;
}
