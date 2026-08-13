/**
 * حالات استخدام الإعلانات
 *
 * تشبيه: لوحة الإعلانات عند باب النادي. الإعلان الإلزامي مثل
 * تعليمات السلامة الجديدة: لا تنزل على البساط قبل أن توقّع أنك قرأتها.
 */

import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AnnouncementRepository,
  AuditLogger,
  AuthenticatedUser,
  Clock,
} from '../ports';

export interface AnnouncementDeps {
  announcements: AnnouncementRepository;
  clock: Clock;
  audit: AuditLogger;
}

/** الإعلانات التي لم يقرأها المستخدم بعد وتنطبق عليه الآن */
export async function getPendingAnnouncements(deps: AnnouncementDeps, user: AuthenticatedUser) {
  return deps.announcements.findPendingFor(user, deps.clock.now());
}

/** "قرأت وفهمت" — نسجّل الإيصال حتى لا يظهر الإعلان مرة أخرى */
export async function acknowledgeAnnouncement(
  deps: AnnouncementDeps,
  user: AuthenticatedUser,
  announcementId: string,
) {
  const now = deps.clock.now();
  await deps.announcements.acknowledge(announcementId, user.id, now);
  await deps.audit.record({
    actorId: user.id,
    action: 'announcement.acknowledged',
    entity: 'Announcement',
    entityId: announcementId,
  });
}

export interface BroadcastInput {
  title: string;
  body: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  audience: 'ALL' | 'MANAGERS_ONLY' | 'STAFF_ONLY' | 'SINGLE_BRANCH';
  branchId?: string | null;
  isMandatory: boolean;
  startsAt?: Date;
  endsAt?: Date | null;
}

/** بثّ إعلان — السوبر أدمن فقط */
export async function broadcastAnnouncement(
  deps: AnnouncementDeps,
  actor: AuthenticatedUser,
  input: BroadcastInput,
) {
  // التحقق من الصلاحية يحدث هنا أيضاً، وليس في الواجهة فقط.
  // القاعدة: من يملك البيانات هو من يحرسها.
  if (!actor.permissions.includes(PERMISSIONS.ANNOUNCEMENT_BROADCAST)) {
    throw Errors.forbidden(PERMISSIONS.ANNOUNCEMENT_BROADCAST);
  }

  const title = input.title?.trim();
  const body = input.body?.trim();
  if (!title || title.length < 3) throw Errors.validation('عنوان الإعلان قصير جداً.');
  if (!body || body.length < 3) throw Errors.validation('نص الإعلان قصير جداً.');
  if (title.length > 140) throw Errors.validation('العنوان يجب أن يكون 140 حرفاً أو أقل.');
  if (body.length > 4000) throw Errors.validation('النص طويل جداً (الحد 4000 حرف).');

  if (input.audience === 'SINGLE_BRANCH' && !input.branchId) {
    throw Errors.validation('اختر الفرع المستهدف.');
  }

  const now = deps.clock.now();
  const startsAt = input.startsAt ?? now;
  if (input.endsAt && input.endsAt <= startsAt) {
    throw Errors.validation('تاريخ الانتهاء يجب أن يكون بعد تاريخ البدء.');
  }

  const created = await deps.announcements.create({
    title,
    body,
    severity: input.severity,
    audience: input.audience,
    branchId: input.audience === 'SINGLE_BRANCH' ? input.branchId! : null,
    isMandatory: input.isMandatory,
    startsAt,
    endsAt: input.endsAt ?? null,
    createdById: actor.id,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'announcement.broadcast',
    entity: 'Announcement',
    entityId: created.id,
    metadata: { audience: input.audience, severity: input.severity, isMandatory: input.isMandatory },
  });

  return created;
}
