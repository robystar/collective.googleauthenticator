# coding=utf-8
from plone.app.testing import applyProfile
from plone.app.testing import PloneSandboxLayer
from plone.app.testing import applyProfile
from plone.app.testing import PLONE_FIXTURE
from plone.app.testing import IntegrationTesting
from plone.app.testing import FunctionalTesting
from plone.app.robotframework.testing import REMOTE_LIBRARY_BUNDLE_FIXTURE
from plone.testing import z2

from zope.configuration import xmlconfig


class CollectivegoogleauthenticatorLayer(PloneSandboxLayer):

    defaultBases = (PLONE_FIXTURE,)

    def setUpZope(self, app, configurationContext):
        # Load ZCML
        import collective.googleauthenticator

        self.loadZCML(package=collective.googleauthenticator)

    def setUpPloneSite(self, portal):
        applyProfile(portal, "collective.googleauthenticator:default")


COLLECTIVE_GOOGLEAUTHENTICATOR_FIXTURE = CollectivegoogleauthenticatorLayer()
COLLECTIVE_GOOGLEAUTHENTICATOR_INTEGRATION_TESTING = IntegrationTesting(
    bases=(COLLECTIVE_GOOGLEAUTHENTICATOR_FIXTURE,),
    name="CollectivegoogleauthenticatorLayer:Integration",
)
COLLECTIVE_GOOGLEAUTHENTICATOR_FUNCTIONAL_TESTING = FunctionalTesting(
    bases=(COLLECTIVE_GOOGLEAUTHENTICATOR_FIXTURE, z2.ZSERVER_FIXTURE),
    name="CollectivegoogleauthenticatorLayer:Functional",
)
COLLECTIVE_GOOGLEAUTHENTICATOR_ROBOT_TESTING = FunctionalTesting(
    bases=(
        COLLECTIVE_GOOGLEAUTHENTICATOR_FIXTURE,
        REMOTE_LIBRARY_BUNDLE_FIXTURE,
        z2.ZSERVER_FIXTURE,
    ),
    name="CollectivegoogleauthenticatorLayer:Robot",
)
