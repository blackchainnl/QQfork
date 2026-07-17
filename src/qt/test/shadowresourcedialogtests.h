// Copyright (c) 2026 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TEST_SHADOWRESOURCEDIALOGTESTS_H
#define BITCOIN_QT_TEST_SHADOWRESOURCEDIALOGTESTS_H

#include <QObject>

class ShadowResourceDialogTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void statusAndCompletedOutcome();
    void statusRefreshesWhileOpen();
    void unqualifiedConsentIsExplicitAndOneCall();
    void projectedStorageWarningDoesNotInventConsent();
    void cancellationAndGuiResponsiveness();
    void errorsFailClosed();
    void closeAndReopenPreservesControlNotConsent();
    void shutdownCancelsActiveScanAndIsIdempotent();
    void shutdownSkipsQueuedScanBeforeBackendEntry();
    void destructionCancelsWithoutStrandingWorker();
};

#endif // BITCOIN_QT_TEST_SHADOWRESOURCEDIALOGTESTS_H
