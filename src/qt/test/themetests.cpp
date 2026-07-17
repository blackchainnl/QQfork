// Copyright (c) 2026 The Blackcoin - Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/themetests.h>

#include <qt/accountpage.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/stakingminingpage.h>

#include <QApplication>
#include <QImage>
#include <QLabel>
#include <QListView>
#include <QPainter>
#include <QPalette>
#include <QTest>
#include <QTreeWidget>

#include <cmath>
#include <memory>
#include <utility>

namespace {
constexpr qreal MINIMUM_TEXT_CONTRAST{4.5};

QPalette LightPalette()
{
    QPalette palette;
    palette.setColor(QPalette::Window, QColor{250, 250, 250});
    palette.setColor(QPalette::WindowText, QColor{23, 23, 23});
    palette.setColor(QPalette::Base, QColor{255, 255, 255});
    palette.setColor(QPalette::AlternateBase, QColor{239, 242, 245});
    palette.setColor(QPalette::Text, QColor{18, 18, 18});
    palette.setColor(QPalette::Button, QColor{242, 242, 242});
    palette.setColor(QPalette::ButtonText, QColor{18, 18, 18});
    palette.setColor(QPalette::Highlight, QColor{0, 82, 147});
    palette.setColor(QPalette::HighlightedText, QColor{255, 255, 255});
    return palette;
}

QPalette DarkPalette()
{
    QPalette palette;
    palette.setColor(QPalette::Window, QColor{32, 33, 36});
    palette.setColor(QPalette::WindowText, QColor{241, 243, 244});
    palette.setColor(QPalette::Base, QColor{23, 24, 26});
    palette.setColor(QPalette::AlternateBase, QColor{43, 45, 49});
    palette.setColor(QPalette::Text, QColor{245, 245, 245});
    palette.setColor(QPalette::Button, QColor{48, 49, 52});
    palette.setColor(QPalette::ButtonText, QColor{245, 245, 245});
    palette.setColor(QPalette::Highlight, QColor{138, 180, 248});
    palette.setColor(QPalette::HighlightedText, QColor{16, 18, 20});
    return palette;
}

void VerifyContrast(const QColor& foreground, const QColor& background, const char* context)
{
    const qreal ratio = GUIUtil::ColorContrastRatio(foreground, background);
    QVERIFY2(ratio >= MINIMUM_TEXT_CONTRAST,
             qPrintable(QStringLiteral("%1 contrast was %2").arg(QString::fromLatin1(context)).arg(ratio, 0, 'f', 2)));
}

void VerifyRenderedBackground(QLabel* label, const QColor& expected)
{
    label->resize(360, 96);
    label->ensurePolished();

    QImage image(label->size(), QImage::Format_RGB32);
    image.fill(Qt::magenta);
    QPainter painter(&image);
    label->render(&painter);
    painter.end();

    int matching_pixels{0};
    int inspected_pixels{0};
    for (int y = 3; y < image.height() - 3; ++y) {
        for (int x = 3; x < image.width() - 3; ++x) {
            const QColor pixel = image.pixelColor(x, y);
            const int distance = std::abs(pixel.red() - expected.red()) +
                                 std::abs(pixel.green() - expected.green()) +
                                 std::abs(pixel.blue() - expected.blue());
            if (distance <= 3) ++matching_pixels;
            ++inspected_pixels;
        }
    }
    QVERIFY2(matching_pixels > inspected_pixels / 3, qPrintable(QStringLiteral("%1 did not render its palette background").arg(label->objectName())));
}

void VerifyPanel(QLabel* label, QPalette::ColorRole background_role, QPalette::ColorRole foreground_role)
{
    QVERIFY(label);
    QVERIFY2(label->autoFillBackground(), qPrintable(label->objectName()));
    QCOMPARE(label->backgroundRole(), background_role);
    QCOMPARE(label->foregroundRole(), foreground_role);
    QVERIFY2(label->styleSheet().isEmpty(), qPrintable(label->objectName()));

    const QColor background = label->palette().color(background_role);
    const QColor foreground = label->palette().color(foreground_role);
    VerifyContrast(foreground, background, qPrintable(label->objectName()));
}

QLabel* RequiredLabel(QWidget& page, const char* object_name)
{
    return page.findChild<QLabel*>(QString::fromLatin1(object_name));
}

void VerifyTransparentLabel(QWidget& page, const char* object_name)
{
    QLabel* label = RequiredLabel(page, object_name);
    QVERIFY2(label, object_name);
    QVERIFY2(label->styleSheet().isEmpty(), object_name);
    const QColor foreground = label->palette().color(label->foregroundRole());
    const QColor background = label->palette().color(QPalette::Window);
    VerifyContrast(foreground, background, object_name);
}
} // namespace

void ThemeTests::walletPagesFollowLightAndDarkPalettes()
{
    std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate(QStringLiteral("other"))};
    QVERIFY(platform_style);

    StakingMiningPage staking_page{platform_style.get()};
    AccountPage account_page{platform_style.get()};
    OverviewPage overview_page{platform_style.get()};

    for (const QPalette& palette : {LightPalette(), DarkPalette()}) {
        for (const auto& roles : {
                 std::pair{QPalette::Base, QPalette::Text},
                 std::pair{QPalette::AlternateBase, QPalette::Text},
                 std::pair{QPalette::Highlight, QPalette::HighlightedText}}) {
            QLabel render_probe{QStringLiteral("Palette render probe")};
            render_probe.setObjectName(QStringLiteral("paletteRenderProbe"));
            render_probe.setPalette(palette);
            GUIUtil::ConfigureThemedLabelPanel(&render_probe, roles.first, roles.second, 10);
            VerifyContrast(render_probe.palette().color(roles.second), render_probe.palette().color(roles.first), "render probe");
            VerifyRenderedBackground(&render_probe, render_probe.palette().color(roles.first));
        }

        staking_page.setPalette(palette);
        account_page.setPalette(palette);
        overview_page.setPalette(palette);
        qApp->processEvents();

        VerifyPanel(RequiredLabel(staking_page, "stakingMiningDashboardAction"), QPalette::Highlight, QPalette::HighlightedText);
        for (const char* name : {"stakingMiningDashboardWallet", "stakingMiningDashboardPos", "stakingMiningDashboardPow", "stakingMiningDashboardColdstake"}) {
            VerifyPanel(RequiredLabel(staking_page, name), QPalette::Base, QPalette::Text);
        }
        for (const char* name : {"stakingSummary", "coldstakeSummary"}) {
            VerifyPanel(RequiredLabel(staking_page, name), QPalette::AlternateBase, QPalette::Text);
        }
        VerifyPanel(RequiredLabel(staking_page, "powWarning"), QPalette::Highlight, QPalette::HighlightedText);
        for (const char* name : {"quantumLegacyUnlockNote", "stakingStatus", "stakeWeight", "goldrushBadge", "posGoldrushStatus", "powStatus"}) {
            VerifyTransparentLabel(staking_page, name);
        }

        for (const char* name : {"accountTotalCard", "accountLegacyCard", "accountQuantumCard"}) {
            VerifyPanel(RequiredLabel(account_page, name), QPalette::Base, QPalette::Text);
        }
        VerifyPanel(RequiredLabel(account_page, "accountAttentionCard"), QPalette::Highlight, QPalette::HighlightedText);
        QTreeWidget* account_tree = account_page.findChild<QTreeWidget*>(QStringLiteral("accountCoinTree"));
        QVERIFY(account_tree);
        VerifyContrast(account_tree->palette().color(QPalette::Text), account_tree->palette().color(QPalette::Base), "account tree");
        VerifyContrast(account_tree->palette().color(QPalette::Text), account_tree->palette().color(QPalette::AlternateBase), "account alternating row");

        for (const char* name : {
                 "labelUnconfirmed", "labelImmature", "labelTotal", "labelDonations", "labelBalance", "labelSpendable", "labelStake",
                 "labelWatchPending", "labelWatchImmature", "labelWatchTotal", "labelWatchAvailable", "labelWatchStake",
                 "overviewLegacyBalanceText", "overviewLegacyBalance", "overviewQuantumBalanceText", "overviewQuantumBalance"}) {
            VerifyTransparentLabel(overview_page, name);
        }
        QListView* transactions = overview_page.findChild<QListView*>(QStringLiteral("listTransactions"));
        QVERIFY(transactions);
        QVERIFY(transactions->parentWidget());
        const QPalette transaction_background_palette = transactions->parentWidget()->palette();
        VerifyContrast(transaction_background_palette.color(QPalette::WindowText), transaction_background_palette.color(QPalette::Window), "recent transactions");
    }
}

void ThemeTests::transactionColorsMeetContrastTarget()
{
    for (const QPalette& palette : {LightPalette(), DarkPalette()}) {
        for (QPalette::ColorRole background_role : {QPalette::Window, QPalette::Base, QPalette::AlternateBase}) {
            const QColor background = palette.color(background_role);
            const QColor foreground = palette.color(background_role == QPalette::Window ? QPalette::WindowText : QPalette::Text);
            const QColor negative = GUIUtil::ReadableColor(COLOR_NEGATIVE, background, foreground);
            const QColor unconfirmed = GUIUtil::ReadableColor(COLOR_UNCONFIRMED, background, foreground);

            VerifyContrast(negative, background, "negative transaction amount");
            VerifyContrast(unconfirmed, background, "unconfirmed transaction amount");
            QVERIFY(negative.red() > negative.green());
            QVERIFY(negative.red() > negative.blue());
            QCOMPARE(unconfirmed.red(), unconfirmed.green());
            QCOMPARE(unconfirmed.green(), unconfirmed.blue());
        }
    }

    const QColor legacy_red = COLOR_NEGATIVE;
    const QColor adapted_red = GUIUtil::ReadableColor(legacy_red, Qt::white, Qt::black);
    QVERIFY(GUIUtil::ColorContrastRatio(legacy_red, Qt::white) < MINIMUM_TEXT_CONTRAST);
    QVERIFY(adapted_red != legacy_red);
    VerifyContrast(adapted_red, Qt::white, "adapted legacy negative color");
}
