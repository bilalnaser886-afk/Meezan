/**
 * كتالوج الصلاحيات (Permissions Catalog)
 *
 * تشبيه: هذه "قائمة الحركات المعتمدة" في نادي الـ MMA.
 * كل حركة لها اسم واحد ثابت، والأحزمة (الأدوار) تُبنى بتجميع حركات.
 *
 * قاعدة ذهبية: لا تكتب اسم صلاحية كنص حرّ في أي مكان آخر بالمشروع.
 * استوردها من هنا دائماً، حتى يخبرك المحرّر فوراً لو أخطأت في الحرف.
 */

export const PERMISSIONS = {
  // ── المبيعات ──
  SALES_CREATE: 'sales.create',
  SALES_VIEW_OWN: 'sales.view_own',
  SALES_VIEW_BRANCH: 'sales.view_branch',
  SALES_VIEW_ALL: 'sales.view_all',
  SALES_REFUND: 'sales.refund',

  // ── العملاء ──
  CUSTOMER_CREATE: 'customer.create',
  CUSTOMER_VIEW: 'customer.view',
  CUSTOMER_EDIT: 'customer.edit',

  // ── المصروفات ──
  EXPENSE_CREATE: 'expense.create',
  EXPENSE_APPROVE: 'expense.approve',

  // ── المخزون ──
  INVENTORY_VIEW: 'inventory.view',
  INVENTORY_ADJUST: 'inventory.adjust',
  INVENTORY_AUDIT: 'inventory.audit',

  // ── التقارير والأرباح ──
  // الفرق الجوهري: المدير يرى "الهامش المعلن"، والمالك وحده يرى التكلفة الحقيقية.
  REPORT_VIEW_BRANCH: 'report.view_branch',
  REPORT_VIEW_GLOBAL: 'report.view_global',
  PROFIT_VIEW_DISPLAY: 'profit.view_display',
  PROFIT_VIEW_REAL: 'profit.view_real',

  // ── إدارة المستخدمين ──
  USER_VIEW: 'user.view',
  USER_CREATE: 'user.create',
  USER_EDIT: 'user.edit',
  USER_SOFT_DELETE: 'user.soft_delete',
  USER_HARD_DELETE: 'user.hard_delete',

  // ── الأرشيف والحذف ──
  RECORD_VIEW_DELETED: 'record.view_deleted',
  RECORD_RESTORE: 'record.restore',
  RECORD_HARD_DELETE: 'record.hard_delete',

  // ── الفروع ──
  BRANCH_VIEW: 'branch.view',
  BRANCH_MANAGE: 'branch.manage',

  // ── الإعلانات ──
  ANNOUNCEMENT_VIEW: 'announcement.view',
  ANNOUNCEMENT_BROADCAST: 'announcement.broadcast',

  // ── التنبيهات وسجل التدقيق ──
  ALERT_VIEW: 'alert.view',
  AUDIT_LOG_VIEW: 'audit_log.view',
} as const;

export type PermissionKey = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

/** وصف كل صلاحية — يُستخدم في بذرة قاعدة البيانات وفي شاشة إدارة الصلاحيات */
export const PERMISSION_META: Record<PermissionKey, { group: string; description: string }> = {
  [PERMISSIONS.SALES_CREATE]: { group: 'المبيعات', description: 'إنشاء فاتورة بيع من نقطة البيع' },
  [PERMISSIONS.SALES_VIEW_OWN]: { group: 'المبيعات', description: 'عرض مبيعاته هو فقط' },
  [PERMISSIONS.SALES_VIEW_BRANCH]: { group: 'المبيعات', description: 'عرض كل مبيعات فرعه' },
  [PERMISSIONS.SALES_VIEW_ALL]: { group: 'المبيعات', description: 'عرض مبيعات كل الفروع' },
  [PERMISSIONS.SALES_REFUND]: { group: 'المبيعات', description: 'تنفيذ مرتجع' },
  [PERMISSIONS.CUSTOMER_CREATE]: { group: 'العملاء', description: 'تسجيل عميل جديد' },
  [PERMISSIONS.CUSTOMER_VIEW]: { group: 'العملاء', description: 'عرض بيانات العملاء' },
  [PERMISSIONS.CUSTOMER_EDIT]: { group: 'العملاء', description: 'تعديل بيانات العملاء' },
  [PERMISSIONS.EXPENSE_CREATE]: { group: 'المصروفات', description: 'تسجيل مصروف' },
  [PERMISSIONS.EXPENSE_APPROVE]: { group: 'المصروفات', description: 'اعتماد المصروفات' },
  [PERMISSIONS.INVENTORY_VIEW]: { group: 'المخزون', description: 'عرض أرصدة المخزون' },
  [PERMISSIONS.INVENTORY_ADJUST]: { group: 'المخزون', description: 'تسوية كميات المخزون' },
  [PERMISSIONS.INVENTORY_AUDIT]: { group: 'المخزون', description: 'تنفيذ جرد ومطابقة' },
  [PERMISSIONS.REPORT_VIEW_BRANCH]: { group: 'التقارير', description: 'تقارير الفرع' },
  [PERMISSIONS.REPORT_VIEW_GLOBAL]: { group: 'التقارير', description: 'تقارير كل الفروع' },
  [PERMISSIONS.PROFIT_VIEW_DISPLAY]: { group: 'التقارير', description: 'عرض الهامش المعلن' },
  [PERMISSIONS.PROFIT_VIEW_REAL]: { group: 'التقارير', description: 'عرض الربح الحقيقي والتكلفة الفعلية' },
  [PERMISSIONS.USER_VIEW]: { group: 'المستخدمون', description: 'عرض المستخدمين' },
  [PERMISSIONS.USER_CREATE]: { group: 'المستخدمون', description: 'إضافة مستخدم' },
  [PERMISSIONS.USER_EDIT]: { group: 'المستخدمون', description: 'تعديل مستخدم' },
  [PERMISSIONS.USER_SOFT_DELETE]: { group: 'المستخدمون', description: 'أرشفة مستخدم' },
  [PERMISSIONS.USER_HARD_DELETE]: { group: 'المستخدمون', description: 'حذف نهائي لمستخدم' },
  [PERMISSIONS.RECORD_VIEW_DELETED]: { group: 'الأرشيف', description: 'عرض السجلات المؤرشفة' },
  [PERMISSIONS.RECORD_RESTORE]: { group: 'الأرشيف', description: 'استرجاع سجل مؤرشف' },
  [PERMISSIONS.RECORD_HARD_DELETE]: { group: 'الأرشيف', description: 'حذف نهائي لأي سجل' },
  [PERMISSIONS.BRANCH_VIEW]: { group: 'الفروع', description: 'عرض الفروع' },
  [PERMISSIONS.BRANCH_MANAGE]: { group: 'الفروع', description: 'إضافة وتعديل الفروع' },
  [PERMISSIONS.ANNOUNCEMENT_VIEW]: { group: 'الإعلانات', description: 'استقبال الإعلانات' },
  [PERMISSIONS.ANNOUNCEMENT_BROADCAST]: { group: 'الإعلانات', description: 'بثّ إعلان إلزامي' },
  [PERMISSIONS.ALERT_VIEW]: { group: 'التنبيهات', description: 'عرض تنبيهات النظام' },
  [PERMISSIONS.AUDIT_LOG_VIEW]: { group: 'التدقيق', description: 'عرض سجل التدقيق' },
};

/**
 * خريطة الأحزمة: أي دور يملك أي صلاحيات.
 * لاحظ ما هو **غائب** عمداً عن مدير الفرع:
 *   - PROFIT_VIEW_REAL      (الربح الحقيقي)
 *   - RECORD_HARD_DELETE    (الحذف النهائي)
 *   - USER_HARD_DELETE
 *   - ANNOUNCEMENT_BROADCAST
 * الغياب هنا هو التصميم الأمني نفسه، وليس نسياناً.
 */
export const ROLE_PERMISSIONS: Record<'SUPER_ADMIN' | 'BRANCH_MANAGER' | 'STAFF', PermissionKey[]> = {
  SUPER_ADMIN: Object.values(PERMISSIONS), // صلاحية مطلقة

  BRANCH_MANAGER: [
    PERMISSIONS.SALES_CREATE,
    PERMISSIONS.SALES_VIEW_OWN,
    PERMISSIONS.SALES_VIEW_BRANCH,
    PERMISSIONS.SALES_REFUND,
    PERMISSIONS.CUSTOMER_CREATE,
    PERMISSIONS.CUSTOMER_VIEW,
    PERMISSIONS.CUSTOMER_EDIT,
    PERMISSIONS.EXPENSE_CREATE,
    PERMISSIONS.EXPENSE_APPROVE,
    PERMISSIONS.INVENTORY_VIEW,
    PERMISSIONS.INVENTORY_ADJUST,
    PERMISSIONS.INVENTORY_AUDIT,
    PERMISSIONS.REPORT_VIEW_BRANCH,
    PERMISSIONS.PROFIT_VIEW_DISPLAY,
    PERMISSIONS.USER_VIEW,
    PERMISSIONS.USER_CREATE,
    PERMISSIONS.USER_EDIT,
    PERMISSIONS.USER_SOFT_DELETE,
    PERMISSIONS.BRANCH_VIEW,
    PERMISSIONS.ANNOUNCEMENT_VIEW,
    PERMISSIONS.ALERT_VIEW,
  ],

  STAFF: [
    PERMISSIONS.SALES_CREATE,
    PERMISSIONS.SALES_VIEW_OWN,
    PERMISSIONS.CUSTOMER_CREATE,
    PERMISSIONS.CUSTOMER_VIEW,
    PERMISSIONS.EXPENSE_CREATE,
    PERMISSIONS.INVENTORY_VIEW,
    PERMISSIONS.ANNOUNCEMENT_VIEW,
  ],
};
