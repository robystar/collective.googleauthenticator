# coding=utf-8
from .interfaces import IGoogleAuthenticatorLayer
from plone import api
from plone.app.users.browser.account import AccountPanelSchemaAdapter
from plone.app.users.browser.userdatapanel import UserDataPanel
from plone.supermodel import model
from plone.z3cform.fieldsets import extensible
from Products.PluggableAuthService.interfaces.authservice import IBasicUser
from Products.PluggableAuthService.interfaces.events import IPrincipalCreatedEvent
from z3c.form import field
from zope.component import adapter
from zope.component import adapts
from zope.i18nmessageid import MessageFactory
from zope.interface import Interface
from zope.schema import Bool
from zope.schema import TextLine

import logging


logger = logging.getLogger("collective.googleauthenticator")

_ = MessageFactory('collective.googleauthenticator')


@adapter(IBasicUser, IPrincipalCreatedEvent)
def userCreatedHandler(principal, event):
    """
    Fired upon creation of each user. If app setting ``globally_enabled`` is set to True,
    two-step verification would be automatically enabled for the registered users (in that
    case they would have to go through the bar-code recovery procedure.

    The ``principal`` value is seems to be a user object, although it does not have
    the ``setMemberProperties`` method defined (that's why we obtain the user
    using `plone.api`, 'cause that one has it).
    """
    from collective.googleauthenticator.helpers import get_or_create_secret
    from collective.googleauthenticator.helpers import is_two_factor_authentication_globally_enabled
    user = api.user.get(username=principal.getId())
    if is_two_factor_authentication_globally_enabled():
        get_or_create_secret(user)
        user.setMemberProperties(mapping={'enable_two_factor_authentication': True,})

    logger.debug(user.getProperty('enable_two_factor_authentication'))
    logger.debug(user.getProperty('two_factor_authentication_secret'))


class IEnhancedUserDataSchema(model.Schema):
    """
    Extended user profile.
    :property bool enable_two_factor_authentication: Indicates, whether the two-step verification is
                                                     enabled for the user.
    :property string two_factor_authentication_secret: Secret key of the user (unique per user). Automatically
                                                       generated.
    :property string bar_code_reset_token: Token to reset users' bar-code. Automatically generated.
    """

    enable_two_factor_authentication = Bool(
        title=_('Enable two-step verification.'),
        description=_("""<strong>Enable two-step verification.</strong><br>Enable/disable the two-step verification. Click <a href=\"@@setup-two-factor-authentication\"> """
                      """here</a> to set it up or <a href=\"@@disable-two-factor-authentication\">here</a> to """
                      """disable it."""
            ),
        required=False
        )

    two_factor_authentication_secret = TextLine(
        title = _('Secret key'),
        description = _('Automatically generated'),
        required = False,
    )

    bar_code_reset_token = TextLine(
        title = _('Token to reset the bar code'),
        description = _('Automatically generated'),
        required = False,
    )


class EnhancedUserDataSchemaAdapter(AccountPanelSchemaAdapter):
    schema = IEnhancedUserDataSchema


class UserDataPanelExtender(extensible.FormExtender):
    adapts(Interface, IGoogleAuthenticatorLayer, UserDataPanel)

    def update(self):
        fields = field.Fields(IEnhancedUserDataSchema)
        fields['enable_two_factor_authentication'].mode = 'display'
        fields['two_factor_authentication_secret'].mode = 'display'  # or hidden ?
        fields['bar_code_reset_token'].mode = 'display'  # or hidden ?
        self.add(fields)

