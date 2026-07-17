// Copyright (c) 2026 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/shadowresourcedialogtests.h>

#include <node/shadow_resource_monitor.h>
#include <qt/shadowresourcedialog.h>

#include <QApplication>
#include <QElapsedTimer>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QStyleFactory>
#include <QTest>
#include <QTimer>

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>

namespace {

node::ShadowResourceStatus HealthyStatus()
{
    node::ShadowResourceMeasurements measurements;
    measurements.applicable = true;
    measurements.available = true;
    measurements.height = 5951000;
    measurements.best_block = std::string(64, 'a');
    measurements.estimated_chainstate_bytes = 8ULL * 1024 * 1024 * 1024;
    measurements.filesystem_available_bytes = 1024ULL * 1024 * 1024 * 1024;
    return node::EvaluateShadowResourceStatus(measurements);
}

node::ShadowResourceStatus OutOfEnvelopeStatus()
{
    node::ShadowResourceMeasurements measurements;
    measurements.applicable = true;
    measurements.available = true;
    measurements.height = node::SHADOW_RESOURCE_SUPPORT_THROUGH_HEIGHT + 1;
    measurements.best_block = std::string(64, 'b');
    measurements.estimated_chainstate_bytes = 8ULL * 1024 * 1024 * 1024;
    measurements.filesystem_available_bytes = 1024ULL * 1024 * 1024 * 1024;
    return node::EvaluateShadowResourceStatus(measurements);
}

node::ShadowResourceStatus ProjectedStorageOnlyStatus()
{
    node::ShadowResourceMeasurements measurements;
    measurements.applicable = true;
    measurements.available = true;
    measurements.height = 5951000;
    measurements.best_block = std::string(64, 'c');
    measurements.estimated_chainstate_bytes = 8ULL * 1024 * 1024 * 1024;
    measurements.filesystem_available_bytes = 100ULL * 1024 * 1024 * 1024;
    const node::ShadowResourceStatus status =
        node::EvaluateShadowResourceStatus(measurements);
    Q_ASSERT(!status.operational_envelope_satisfied);
    Q_ASSERT(status.diagnostic_scan_default_authorized);
    return status;
}

class FakeShadowResourceBackend final : public ShadowResourceBackend
{
public:
    explicit FakeShadowResourceBackend(node::ShadowResourceStatus status)
        : m_status(std::move(status))
    {
    }

    node::ShadowResourceStatus resourceStatus() override
    {
        status_calls.fetch_add(1);
        if (block_next_status.exchange(false)) {
            std::unique_lock<std::mutex> lock{m_mutex};
            m_status_blocked = true;
            m_cv.notify_all();
            m_cv.wait(lock, [&] { return m_release_status; });
        }
        if (fail_status.load()) throw std::runtime_error("measurement failed");
        return m_status;
    }

    node::ShadowSupplyScanProgress scanProgress() override
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        return m_progress;
    }

    bool requestAbort() override
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        if (!m_progress.active) return false;
        abort_calls.fetch_add(1);
        m_progress.abort_requested = true;
        m_abort_requested = true;
        m_cv.notify_all();
        return true;
    }

    std::string runSupplyScan(bool allow_unqualified_resource_scan) override
    {
        scan_calls.fetch_add(1);
        last_allow.store(allow_unqualified_resource_scan);
        {
            std::lock_guard<std::mutex> lock{m_mutex};
            m_progress = {};
            m_progress.active = true;
            m_progress.scan_id = static_cast<uint64_t>(scan_calls.load());
            m_progress.height = m_status.height;
            m_progress.best_block = m_status.best_block;
            m_progress.stage = "scanning_utxos";
            m_progress.last_outcome = "running";
            m_progress.utxo_records_scanned = 17;
            m_started = true;
        }
        m_cv.notify_all();

        if (block_scan.load()) {
            std::unique_lock<std::mutex> lock{m_mutex};
            m_cv.wait(lock, [&] { return m_abort_requested; });
        }

        {
            std::lock_guard<std::mutex> lock{m_mutex};
            if (m_abort_requested) {
                m_progress.active = false;
                m_progress.stage = "idle";
                m_progress.last_outcome = "aborted";
                m_progress.last_reason = "Operator cancellation completed";
                throw std::runtime_error("Operator cancellation completed");
            }
            if (fail_scan.load()) {
                m_progress.active = false;
                m_progress.stage = "idle";
                m_progress.last_outcome = "aborted";
                m_progress.last_reason = "synthetic scan failure";
                throw std::runtime_error("synthetic scan failure");
            }
            m_progress.active = false;
            m_progress.stage = "idle";
            m_progress.last_outcome = "complete";
            m_progress.last_reason = "Full immutable-snapshot scan completed";
            m_progress.completed_at_unix = 1234;
        }
        return R"({"schema":"blackcoin.supply.lifecycle.v2","circulating_amount":123.0})";
    }

    bool started() const
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        return m_started;
    }

    void blockNextStatus()
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        m_status_blocked = false;
        m_release_status = false;
        block_next_status.store(true);
    }

    bool statusBlocked() const
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        return m_status_blocked;
    }

    void releaseStatus()
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        m_release_status = true;
        m_cv.notify_all();
    }

    std::atomic<int> status_calls{0};
    std::atomic<int> scan_calls{0};
    std::atomic<int> abort_calls{0};
    std::atomic<bool> last_allow{false};
    std::atomic<bool> block_scan{false};
    std::atomic<bool> fail_scan{false};
    std::atomic<bool> fail_status{false};
    std::atomic<bool> block_next_status{false};

private:
    const node::ShadowResourceStatus m_status;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    node::ShadowSupplyScanProgress m_progress;
    bool m_started{false};
    bool m_abort_requested{false};
    bool m_status_blocked{false};
    bool m_release_status{false};
};

QPushButton* Button(ShadowResourceDialog& dialog, const char* name)
{
    auto* result = dialog.findChild<QPushButton*>(QString::fromLatin1(name));
    Q_ASSERT(result);
    return result;
}

QPlainTextEdit* Text(ShadowResourceDialog& dialog, const char* name)
{
    auto* result = dialog.findChild<QPlainTextEdit*>(QString::fromLatin1(name));
    Q_ASSERT(result);
    return result;
}

void AnswerConsent(bool authorize)
{
    QTimer::singleShot(0, [authorize] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            auto* box = qobject_cast<QMessageBox*>(widget);
            if (!box || box->objectName() !=
                    QLatin1String("shadowResourceConsentDialog")) continue;
            auto* cancel = box->findChild<QPushButton*>(
                QStringLiteral("shadowResourceConsentCancelButton"));
            Q_ASSERT(cancel);
            Q_ASSERT(box->defaultButton() == cancel);
            Q_ASSERT(box->escapeButton() == cancel);
            auto* button = box->findChild<QPushButton*>(authorize
                ? QStringLiteral("shadowResourceAuthorizeOnceButton")
                : QStringLiteral("shadowResourceConsentCancelButton"));
            Q_ASSERT(button);
            QTest::mouseClick(button, Qt::LeftButton);
            return;
        }
        Q_ASSERT(false);
    });
}

} // namespace

void ShadowResourceDialogTests::initTestCase()
{
    // The native macOS style is not compatible with Qt's headless minimal
    // platform and crashes while painting QGroupBox. The production app still
    // uses its configured native style; only this headless test suite uses the
    // portable Fusion painter.
#ifdef Q_OS_MACOS
    if (QApplication::platformName() == QLatin1String("minimal")) {
        QApplication::setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    }
#endif
}

void ShadowResourceDialogTests::statusAndCompletedOutcome()
{
    auto backend = std::make_shared<FakeShadowResourceBackend>(HealthyStatus());
    ShadowResourceDialog dialog{backend};
    dialog.show();

    auto* scan = Button(dialog, "shadowSupplyScanButton");
    QTRY_VERIFY_WITH_TIMEOUT(scan->isEnabled(), 3000);
    const QString details =
        Text(dialog, "shadowResourceStatusDetails")->toPlainText();
    QVERIFY(details.contains(QStringLiteral("Status: healthy")));
    QVERIFY(details.contains(QStringLiteral("Diagnostic scan authorized without override: yes")));
    QVERIFY(details.contains(QStringLiteral("Consensus behavior changed: no")));

    QTest::mouseClick(scan, Qt::LeftButton);
    QTRY_COMPARE_WITH_TIMEOUT(backend->scan_calls.load(), 1, 3000);
    QTRY_VERIFY_WITH_TIMEOUT(
        Text(dialog, "shadowSupplyScanResult")->toPlainText().contains(
            QStringLiteral("blackcoin.supply.lifecycle.v2")), 3000);
    QVERIFY(!backend->last_allow.load());
    QTRY_VERIFY_WITH_TIMEOUT(
        Text(dialog, "shadowSupplyScanDetails")->toPlainText().contains(
            QStringLiteral("Last outcome: complete")), 3000);
}

void ShadowResourceDialogTests::statusRefreshesWhileOpen()
{
    auto backend = std::make_shared<FakeShadowResourceBackend>(HealthyStatus());
    ShadowResourceDialog dialog{backend};
    dialog.show();
    QTRY_VERIFY_WITH_TIMEOUT(
        Button(dialog, "shadowSupplyScanButton")->isEnabled(), 3000);
    const int initial_calls = backend->status_calls.load();
    QVERIFY(initial_calls >= 1);

    auto* timer = dialog.findChild<QTimer*>(
        QStringLiteral("shadowResourceStatusRefreshTimer"));
    QVERIFY(timer);
    QVERIFY(timer->isActive());
    QVERIFY(QMetaObject::invokeMethod(timer, "timeout", Qt::DirectConnection));
    QTRY_VERIFY_WITH_TIMEOUT(backend->status_calls.load() > initial_calls, 3000);
}

void ShadowResourceDialogTests::unqualifiedConsentIsExplicitAndOneCall()
{
    auto backend =
        std::make_shared<FakeShadowResourceBackend>(OutOfEnvelopeStatus());
    ShadowResourceDialog dialog{backend};
    dialog.show();
    auto* scan = Button(dialog, "shadowSupplyScanButton");
    QTRY_VERIFY_WITH_TIMEOUT(scan->isEnabled(), 3000);

    AnswerConsent(false);
    QTest::mouseClick(scan, Qt::LeftButton);
    QCOMPARE(backend->scan_calls.load(), 0);

    AnswerConsent(true);
    QTest::mouseClick(scan, Qt::LeftButton);
    QTRY_COMPARE_WITH_TIMEOUT(backend->scan_calls.load(), 1, 3000);
    QVERIFY(backend->last_allow.load());
    QTRY_VERIFY_WITH_TIMEOUT(scan->isEnabled(), 3000);

    // Closing and reopening the surface must not turn the prior one-call
    // authorization into a stored preference.
    dialog.close();
    dialog.show();
    QTRY_VERIFY_WITH_TIMEOUT(scan->isEnabled(), 3000);
    AnswerConsent(false);
    QTest::mouseClick(scan, Qt::LeftButton);
    QCOMPARE(backend->scan_calls.load(), 1);
}

void ShadowResourceDialogTests::projectedStorageWarningDoesNotInventConsent()
{
    const node::ShadowResourceStatus status = ProjectedStorageOnlyStatus();
    QVERIFY(!status.within_projected_free_space);
    QVERIFY(status.within_immediate_scan_free_space);
    QVERIFY(status.diagnostic_scan_default_authorized);

    auto backend = std::make_shared<FakeShadowResourceBackend>(status);
    ShadowResourceDialog dialog{backend};
    dialog.show();
    auto* scan = Button(dialog, "shadowSupplyScanButton");
    QTRY_VERIFY_WITH_TIMEOUT(scan->isEnabled(), 3000);
    QTest::mouseClick(scan, Qt::LeftButton);
    QTRY_COMPARE_WITH_TIMEOUT(backend->scan_calls.load(), 1, 3000);
    QVERIFY(!backend->last_allow.load());
}

void ShadowResourceDialogTests::cancellationAndGuiResponsiveness()
{
    auto backend = std::make_shared<FakeShadowResourceBackend>(HealthyStatus());
    backend->block_scan.store(true);
    ShadowResourceDialog dialog{backend};
    dialog.show();
    auto* scan = Button(dialog, "shadowSupplyScanButton");
    auto* cancel = Button(dialog, "shadowSupplyAbortButton");
    QTRY_VERIFY_WITH_TIMEOUT(scan->isEnabled(), 3000);

    int heartbeat{0};
    QTimer timer;
    timer.setInterval(10);
    QObject::connect(&timer, &QTimer::timeout, [&] { ++heartbeat; });
    timer.start();

    QTest::mouseClick(scan, Qt::LeftButton);
    QTRY_VERIFY_WITH_TIMEOUT(backend->started(), 3000);
    QTest::qWait(150);
    QVERIFY2(heartbeat >= 5, "The supply scan blocked the Qt event loop");
    QTRY_VERIFY_WITH_TIMEOUT(cancel->isEnabled(), 3000);

    QTest::mouseClick(cancel, Qt::LeftButton);
    QTRY_COMPARE_WITH_TIMEOUT(backend->abort_calls.load(), 1, 3000);
    QTRY_VERIFY_WITH_TIMEOUT(
        Text(dialog, "shadowSupplyScanDetails")->toPlainText().contains(
            QStringLiteral("Last outcome: aborted")), 3000);
    QTRY_VERIFY_WITH_TIMEOUT(
        Text(dialog, "shadowSupplyScanResult")->toPlainText().contains(
            QStringLiteral("did not return a monetary result"),
            Qt::CaseInsensitive), 3000);
    const QString cancel_result =
        Text(dialog, "shadowSupplyScanResult")->toPlainText();
    QVERIFY2(cancel_result.contains(QStringLiteral("Operator cancellation")),
             qPrintable(cancel_result));
}

void ShadowResourceDialogTests::errorsFailClosed()
{
    {
        auto backend = std::make_shared<FakeShadowResourceBackend>(HealthyStatus());
        backend->fail_status.store(true);
        ShadowResourceDialog dialog{backend};
        dialog.show();
        auto* summary = dialog.findChild<QLabel*>(
            QStringLiteral("shadowResourceStatusSummary"));
        auto* scan = Button(dialog, "shadowSupplyScanButton");
        QTRY_VERIFY_WITH_TIMEOUT(
            summary->text().contains(QStringLiteral("measurement failed")), 3000);
        QVERIFY(!scan->isEnabled());
    }

    {
        auto backend = std::make_shared<FakeShadowResourceBackend>(HealthyStatus());
        backend->fail_scan.store(true);
        ShadowResourceDialog dialog{backend};
        dialog.show();
        auto* scan = Button(dialog, "shadowSupplyScanButton");
        QTRY_VERIFY_WITH_TIMEOUT(scan->isEnabled(), 3000);
        QTest::mouseClick(scan, Qt::LeftButton);
        QTRY_VERIFY_WITH_TIMEOUT(
            Text(dialog, "shadowSupplyScanResult")->toPlainText().contains(
                QStringLiteral("synthetic scan failure")), 3000);
        QVERIFY(Text(dialog, "shadowSupplyScanResult")->toPlainText().contains(
            QStringLiteral("did not return a monetary result")));
    }
}

void ShadowResourceDialogTests::closeAndReopenPreservesControlNotConsent()
{
    auto backend = std::make_shared<FakeShadowResourceBackend>(HealthyStatus());
    backend->block_scan.store(true);
    ShadowResourceDialog dialog{backend};
    dialog.show();
    auto* scan = Button(dialog, "shadowSupplyScanButton");
    auto* cancel = Button(dialog, "shadowSupplyAbortButton");
    QTRY_VERIFY_WITH_TIMEOUT(scan->isEnabled(), 3000);
    QTest::mouseClick(scan, Qt::LeftButton);
    QTRY_VERIFY_WITH_TIMEOUT(backend->started(), 3000);

    dialog.close();
    QCOMPARE(backend->abort_calls.load(), 0);
    dialog.show();
    QTRY_VERIFY_WITH_TIMEOUT(cancel->isEnabled(), 3000);
    QTest::mouseClick(cancel, Qt::LeftButton);
    QTRY_COMPARE_WITH_TIMEOUT(backend->abort_calls.load(), 1, 3000);
}

void ShadowResourceDialogTests::shutdownCancelsActiveScanAndIsIdempotent()
{
    auto backend = std::make_shared<FakeShadowResourceBackend>(HealthyStatus());
    backend->block_scan.store(true);
    ShadowResourceDialog dialog{backend};
    dialog.show();
    auto* scan = Button(dialog, "shadowSupplyScanButton");
    QTRY_VERIFY_WITH_TIMEOUT(scan->isEnabled(), 3000);
    QTest::mouseClick(scan, Qt::LeftButton);
    QTRY_VERIFY_WITH_TIMEOUT(backend->started(), 3000);

    QElapsedTimer elapsed;
    elapsed.start();
    dialog.requestShutdown();
    dialog.join();
    dialog.requestShutdown();
    dialog.join();
    QVERIFY2(elapsed.elapsed() < 2000,
             "Application shutdown stranded the active resource worker");
    QVERIFY(backend->abort_calls.load() >= 1);
}

void ShadowResourceDialogTests::shutdownSkipsQueuedScanBeforeBackendEntry()
{
    auto backend = std::make_shared<FakeShadowResourceBackend>(HealthyStatus());
    ShadowResourceDialog dialog{backend};
    dialog.show();
    auto* refresh = Button(dialog, "shadowResourceRefreshButton");
    auto* scan = Button(dialog, "shadowSupplyScanButton");
    QTRY_VERIFY_WITH_TIMEOUT(scan->isEnabled(), 3000);

    backend->blockNextStatus();
    QTest::mouseClick(refresh, Qt::LeftButton);
    QTRY_VERIFY_WITH_TIMEOUT(backend->statusBlocked(), 3000);
    QTest::mouseClick(scan, Qt::LeftButton);

    dialog.requestShutdown();
    backend->releaseStatus();
    QElapsedTimer elapsed;
    elapsed.start();
    dialog.join();
    QVERIFY2(elapsed.elapsed() < 2000,
             "Queued resource work stranded application shutdown");
    QCOMPARE(backend->scan_calls.load(), 0);
}

void ShadowResourceDialogTests::destructionCancelsWithoutStrandingWorker()
{
    auto backend = std::make_shared<FakeShadowResourceBackend>(HealthyStatus());
    backend->block_scan.store(true);
    auto dialog = std::make_unique<ShadowResourceDialog>(backend);
    dialog->show();
    auto* scan = Button(*dialog, "shadowSupplyScanButton");
    QTRY_VERIFY_WITH_TIMEOUT(scan->isEnabled(), 3000);
    QTest::mouseClick(scan, Qt::LeftButton);
    QTRY_VERIFY_WITH_TIMEOUT(backend->started(), 3000);

    QElapsedTimer elapsed;
    elapsed.start();
    dialog.reset();
    QVERIFY2(elapsed.elapsed() < 2000,
             "Dialog destruction stranded the background supply scan");
    QCOMPARE(backend->abort_calls.load(), 1);
}
