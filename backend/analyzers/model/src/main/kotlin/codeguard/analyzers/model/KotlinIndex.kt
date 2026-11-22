package codeguard.analyzers.model

import org.jetbrains.kotlin.com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.psi.KtBlockExpression
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtClassBody
import org.jetbrains.kotlin.psi.KtClassOrObject
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtNamedDeclaration
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtNameReferenceExpression
import org.jetbrains.kotlin.psi.KtNullableType
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtQualifiedExpression
import org.jetbrains.kotlin.psi.KtTypeReference
import org.jetbrains.kotlin.psi.KtUserType

internal fun indexKotlin(
    files: List<SourceFile>,
    kotlin: Map<String, KtFile>,
): Pair<DeclarationIndex, CallIndex> {
    val sources = files.associateBy(SourceFile::path)
    val declarations = linkedMapOf<String, MutableList<Declaration>>()
    val functions = linkedMapOf<String, MutableList<Pair<KtNamedFunction, Declaration>>>()
    val classes = linkedMapOf<String, MutableList<KtClassOrObject>>()
    for ((path, parsed) in kotlin) {
        val source = sources.getValue(path)
        for (element in PsiTreeUtil.findChildrenOfType(parsed, KtNamedDeclaration::class.java)) {
            val name = element.name ?: continue
            val kind = when (element) {
                is KtClassOrObject -> DeclarationKind.CLASS
                is KtNamedFunction -> DeclarationKind.FUNCTION
                is KtProperty -> if (element.hasModifier(KtTokens.CONST_KEYWORD)) {
                    DeclarationKind.CONSTANT
                } else {
                    DeclarationKind.PROPERTY
                }
                else -> continue
            }
            val packageName = parsed.packageFqName.asString()
            val scope = generateSequence(element.parent) { it.parent }
                .filterIsInstance<KtNamedDeclaration>().mapNotNull { it.name }.toList().asReversed()
            val qualified = (listOf(packageName).filter(String::isNotEmpty) + scope + name).joinToString(".")
            val declaration = Declaration(name, qualified, kind, element.psiLocation(source))
            declarations.getOrPut(name, ::mutableListOf) += declaration
            if (element is KtNamedFunction) functions.getOrPut(name, ::mutableListOf) += element to declaration
            if (element is KtClassOrObject && element.fqName != null) {
                classes.getOrPut(qualified, ::mutableListOf) += element
            }
        }
    }
    val calls = kotlin.mapValues { (path, parsed) ->
        val source = sources.getValue(path)
        PsiTreeUtil.findChildrenOfType(parsed, KtCallExpression::class.java).mapNotNull { call ->
            val callee = call.calleeExpression ?: return@mapNotNull null
            val name = callee.text
            val qualified = (call.parent as? KtQualifiedExpression)?.takeIf { it.selectorExpression == call }
            val receiverClass = qualified?.let { resolveReceiverClass(it, classes) }
            val target = if (qualified != null && receiverClass == null) null else {
                val scope = PsiTreeUtil.getParentOfType(call, KtClassOrObject::class.java)
                val candidates = functions[name].orEmpty().filter { (function, _) ->
                    val owner = PsiTreeUtil.getParentOfType(function, KtClassOrObject::class.java)
                    val targetFile = function.containingKtFile
                    val matchesScope = if (receiverClass != null) {
                        owner == receiverClass && (owner == scope ||
                            (!function.hasModifier(KtTokens.PRIVATE_KEYWORD) &&
                                !function.hasModifier(KtTokens.PROTECTED_KEYWORD)))
                    } else {
                        (scope != null && owner == scope) ||
                            (function.isTopLevel && targetFile.packageFqName == parsed.packageFqName &&
                                (targetFile == parsed || !function.hasModifier(KtTokens.PRIVATE_KEYWORD)))
                    }
                    function.receiverTypeReference == null && !function.isLocal && matchesScope
                }
                candidates.singleOrNull()?.second
            }
            CallSite(name, callee.psiLocation(source), target)
        }
    }
    return DeclarationIndex(declarations.mapValues { it.value.toList() }) to CallIndex(calls)
}

private fun resolveReceiverClass(
    qualified: KtQualifiedExpression,
    classes: Map<String, List<KtClassOrObject>>,
): KtClassOrObject? {
    val receiver = qualified.receiverExpression as? KtNameReferenceExpression ?: return null
    val type = receiverType(qualified, receiver.getReferencedName())?.typeElement ?: return null
    val userType = (if (type is KtNullableType) type.innerType else type) as? KtUserType ?: return null
    val name = generateSequence(userType) { it.qualifier }
        .mapNotNull { it.referenceExpression?.getReferencedName() }
        .toList().asReversed().joinToString(".")
    val file = qualified.containingKtFile
    val prefix = name.substringBefore('.')
    val imports = file.importDirectives.filterNot { it.isAllUnder }.mapNotNull { directive ->
        val imported = directive.importedFqName ?: return@mapNotNull null
        imported.asString().takeIf { (directive.aliasName ?: imported.shortName().asString()) == prefix }
    }
    if (imports.isNotEmpty()) {
        val imported = imports.singleOrNull() ?: return null
        return classes[imported + name.removePrefix(prefix)]?.singleOrNull()
    }
    val inPackage = listOf(file.packageFqName.asString(), name).filter(String::isNotEmpty).joinToString(".")
    val candidates = buildSet {
        add(name)
        add(inPackage)
        file.importDirectives.filter { it.isAllUnder }.mapNotNull { it.importedFqName }.forEach {
            add(it.asString() + "." + name)
        }
    }
    return candidates.flatMap { classes[it].orEmpty() }.singleOrNull()
}

private fun receiverType(qualified: KtQualifiedExpression, name: String): KtTypeReference? {
    for (scope in generateSequence(qualified.parent) { it.parent }) {
        val declarations = when (scope) {
            is KtBlockExpression -> scope.statements.filter { it.textRange.endOffset <= qualified.textOffset }
            is KtClassBody -> scope.declarations
            is KtFile -> scope.declarations
            else -> emptyList()
        }
        val property = declarations.filterIsInstance<KtProperty>().lastOrNull { it.name == name }
        if (property != null) return property.typeReference
        val parameter = when (scope) {
            is KtNamedFunction -> scope.valueParameters.firstOrNull { it.name == name }
            is KtClass -> scope.primaryConstructorParameters.firstOrNull { it.hasValOrVar() && it.name == name }
            else -> null
        }
        if (parameter != null) return parameter.typeReference
    }
    return null
}
