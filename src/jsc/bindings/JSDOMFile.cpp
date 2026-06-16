#include "root.h"
#include "ZigGeneratedClasses.h"
#include "ZigGlobalObject.h"
#include <JavaScriptCore/ObjectConstructor.h>
#include <JavaScriptCore/InternalFunction.h>
#include <JavaScriptCore/FunctionPrototype.h>
#include "ErrorCode.h"
#include "JSDOMFile.h"

using namespace JSC;

extern "C" SYSV_ABI void* JSDOMFile__construct(JSC::JSGlobalObject*, JSC::CallFrame* callframe);

extern "C" SYSV_ABI JSC::EncodedJSValue JSDOMFile__getName(void* ptr, JSC::EncodedJSValue thisValue, JSC::JSGlobalObject* globalObject);
extern "C" SYSV_ABI bool JSDOMFile__setName(void* ptr, JSC::EncodedJSValue thisValue, JSC::JSGlobalObject* globalObject, JSC::EncodedJSValue value);
extern "C" SYSV_ABI JSC::EncodedJSValue JSDOMFile__getLastModified(void* ptr, JSC::JSGlobalObject* globalObject);

namespace Bun {

JSC_DEFINE_CUSTOM_GETTER(domFilePrototype_nameGetter, (JSGlobalObject * lexicalGlobalObject, EncodedJSValue encodedThisValue, PropertyName))
{
    auto& vm = JSC::getVM(lexicalGlobalObject);
    auto throwScope = DECLARE_THROW_SCOPE(vm);
    auto* thisObject = dynamicDowncast<WebCore::JSBlob>(JSValue::decode(encodedThisValue));
    if (!thisObject) [[unlikely]] {
        return JSValue::encode(jsUndefined());
    }
    JSC::EnsureStillAliveScope thisArg = JSC::EnsureStillAliveScope(thisObject);

    if (JSValue cachedValue = thisObject->m_name.get())
        return JSValue::encode(cachedValue);

    JSC::JSValue result = JSC::JSValue::decode(
        JSDOMFile__getName(thisObject->wrapped(), encodedThisValue, lexicalGlobalObject));
    RETURN_IF_EXCEPTION(throwScope, {});
    thisObject->m_name.set(vm, thisObject, result);
    RELEASE_AND_RETURN(throwScope, JSValue::encode(result));
}

JSC_DEFINE_CUSTOM_SETTER(domFilePrototype_nameSetter, (JSGlobalObject * lexicalGlobalObject, EncodedJSValue encodedThisValue, EncodedJSValue encodedValue, PropertyName attributeName))
{
    auto& vm = JSC::getVM(lexicalGlobalObject);
    auto throwScope = DECLARE_THROW_SCOPE(vm);
    auto* thisObject = dynamicDowncast<WebCore::JSBlob>(JSValue::decode(encodedThisValue));
    if (!thisObject) [[unlikely]] {
        return false;
    }
    JSC::EnsureStillAliveScope thisArg = JSC::EnsureStillAliveScope(thisObject);
    bool result = JSDOMFile__setName(thisObject->wrapped(), encodedThisValue, lexicalGlobalObject, encodedValue);
    RELEASE_AND_RETURN(throwScope, result);
}

JSC_DEFINE_CUSTOM_GETTER(domFilePrototype_lastModifiedGetter, (JSGlobalObject * lexicalGlobalObject, EncodedJSValue encodedThisValue, PropertyName))
{
    auto& vm = JSC::getVM(lexicalGlobalObject);
    auto throwScope = DECLARE_THROW_SCOPE(vm);
    auto* thisObject = dynamicDowncast<WebCore::JSBlob>(JSValue::decode(encodedThisValue));
    if (!thisObject) [[unlikely]] {
        return JSValue::encode(jsUndefined());
    }
    JSC::EnsureStillAliveScope thisArg = JSC::EnsureStillAliveScope(thisObject);
    JSC::EncodedJSValue result = JSDOMFile__getLastModified(thisObject->wrapped(), lexicalGlobalObject);
    RETURN_IF_EXCEPTION(throwScope, {});
    RELEASE_AND_RETURN(throwScope, result);
}

static const HashTableValue JSDOMFilePrototypeTableValues[] = {
    { "name"_s, static_cast<unsigned>(PropertyAttribute::CustomAccessor | PropertyAttribute::DontDelete), NoIntrinsic, { HashTableValue::GetterSetterType, domFilePrototype_nameGetter, domFilePrototype_nameSetter } },
    { "lastModified"_s, static_cast<unsigned>(PropertyAttribute::ReadOnly | PropertyAttribute::CustomAccessor | PropertyAttribute::DontDelete), NoIntrinsic, { HashTableValue::GetterSetterType, domFilePrototype_lastModifiedGetter, 0 } },
};

class JSDOMFilePrototype final : public JSC::JSNonFinalObject {
public:
    using Base = JSC::JSNonFinalObject;
    static constexpr unsigned StructureFlags = Base::StructureFlags;

    static JSDOMFilePrototype* create(JSC::VM& vm, JSC::JSGlobalObject* globalObject, JSC::Structure* structure)
    {
        JSDOMFilePrototype* prototype = new (NotNull, JSC::allocateCell<JSDOMFilePrototype>(vm)) JSDOMFilePrototype(vm, structure);
        prototype->finishCreation(vm, globalObject);
        return prototype;
    }

    static JSC::Structure* createStructure(JSC::VM& vm, JSC::JSGlobalObject* globalObject, JSC::JSValue prototype)
    {
        auto* structure = JSC::Structure::create(vm, globalObject, prototype, TypeInfo(JSC::ObjectType, StructureFlags), info());
        structure->setMayBePrototype(true);
        return structure;
    }

    DECLARE_INFO;

    template<typename CellType, JSC::SubspaceAccess>
    static JSC::GCClient::IsoSubspace* subspaceFor(JSC::VM& vm)
    {
        STATIC_ASSERT_ISO_SUBSPACE_SHARABLE(JSDOMFilePrototype, Base);
        return &vm.plainObjectSpace();
    }

private:
    JSDOMFilePrototype(JSC::VM& vm, JSC::Structure* structure)
        : Base(vm, structure)
    {
    }

    void finishCreation(JSC::VM& vm, JSC::JSGlobalObject* globalObject)
    {
        Base::finishCreation(vm);
        reifyStaticProperties(vm, WebCore::JSBlob::info(), JSDOMFilePrototypeTableValues, *this);
        this->putDirect(vm, vm.propertyNames->toStringTagSymbol, jsString(vm, String("File"_s)), PropertyAttribute::DontEnum | PropertyAttribute::ReadOnly | 0);
    }
};

const JSC::ClassInfo JSDOMFilePrototype::s_info = { "File"_s, &Base::s_info, nullptr, nullptr, CREATE_METHOD_TABLE(JSDOMFilePrototype) };

class JSDOMFileConstructor final : public JSC::InternalFunction {
    using Base = JSC::InternalFunction;

public:
    JSDOMFileConstructor(JSC::VM& vm, JSC::Structure* structure)
        : Base(vm, structure, call, construct)
    {
    }

    DECLARE_INFO;

    static constexpr unsigned StructureFlags = Base::StructureFlags;

    template<typename CellType, JSC::SubspaceAccess>
    static JSC::GCClient::IsoSubspace* subspaceFor(JSC::VM& vm)
    {
        return &vm.internalFunctionSpace();
    }
    static JSC::Structure* createStructure(JSC::VM& vm, JSC::JSGlobalObject* globalObject, JSC::JSValue prototype)
    {
        return JSC::Structure::create(vm, globalObject, prototype, JSC::TypeInfo(InternalFunctionType, StructureFlags), info());
    }

    static JSDOMFileConstructor* create(JSC::VM& vm, JSGlobalObject* globalObject)
    {
        auto* zigGlobal = defaultGlobalObject(globalObject);
        auto* structure = createStructure(vm, globalObject, zigGlobal->JSBlobConstructor());
        auto* object = new (NotNull, JSC::allocateCell<JSDOMFileConstructor>(vm)) JSDOMFileConstructor(vm, structure);
        object->finishCreation(vm, globalObject);

        auto* fileStructure = zigGlobal->JSDOMFileStructure();
        auto* prototype = fileStructure->storedPrototypeObject();
        object->putDirect(vm, vm.propertyNames->prototype, prototype, PropertyAttribute::DontEnum | PropertyAttribute::DontDelete | PropertyAttribute::ReadOnly | 0);
        prototype->putDirect(vm, vm.propertyNames->constructor, object, PropertyAttribute::DontEnum | 0);
        return object;
    }

    static JSC_HOST_CALL_ATTRIBUTES JSC::EncodedJSValue construct(JSGlobalObject* lexicalGlobalObject, CallFrame* callFrame)
    {
        auto* globalObject = defaultGlobalObject(lexicalGlobalObject);
        auto& vm = JSC::getVM(globalObject);
        JSObject* newTarget = asObject(callFrame->newTarget());
        auto* constructor = globalObject->JSDOMFileConstructor();
        Structure* structure = globalObject->JSDOMFileStructure();
        if (constructor != newTarget) {
            auto scope = DECLARE_THROW_SCOPE(vm);

            auto* functionGlobalObject = defaultGlobalObject(
                // ShadowRealm functions belong to a different global object.
                getFunctionRealm(lexicalGlobalObject, newTarget));
            RETURN_IF_EXCEPTION(scope, {});
            structure = InternalFunction::createSubclassStructure(lexicalGlobalObject, newTarget, functionGlobalObject->JSDOMFileStructure());
            RETURN_IF_EXCEPTION(scope, {});
        }

        void* ptr = JSDOMFile__construct(lexicalGlobalObject, callFrame);

        if (!ptr) [[unlikely]] {
            return JSValue::encode(JSC::jsUndefined());
        }

        return JSValue::encode(
            WebCore::JSBlob::create(vm, globalObject, structure, ptr));
    }

    static JSC_HOST_CALL_ATTRIBUTES EncodedJSValue call(JSGlobalObject* lexicalGlobalObject, CallFrame* callFrame)
    {
        auto scope = DECLARE_THROW_SCOPE(lexicalGlobalObject->vm());
        throwTypeError(lexicalGlobalObject, scope, "Class constructor File cannot be invoked without 'new'"_s);
        return {};
    }

private:
    void finishCreation(JSC::VM& vm, JSC::JSGlobalObject* globalObject)
    {
        Base::finishCreation(vm, 2, "File"_s);
    }
};

const JSC::ClassInfo JSDOMFileConstructor::s_info = { "File"_s, &Base::s_info, nullptr, nullptr, CREATE_METHOD_TABLE(JSDOMFileConstructor) };

JSC::JSObject* createJSDOMFileConstructor(JSC::VM& vm, JSC::JSGlobalObject* globalObject)
{
    return JSDOMFileConstructor::create(vm, globalObject);
}

JSC::Structure* createJSDOMFileStructure(JSC::VM& vm, JSC::JSGlobalObject* globalObject)
{
    auto* zigGlobal = defaultGlobalObject(globalObject);
    auto* superPrototype = zigGlobal->JSBlobPrototype();
    auto* protoStructure = JSDOMFilePrototype::createStructure(vm, globalObject, superPrototype);
    auto* prototype = JSDOMFilePrototype::create(vm, globalObject, protoStructure);
    return WebCore::JSBlob::createStructure(vm, globalObject, prototype);
}

extern "C" SYSV_ABI JSC::EncodedJSValue BUN__createJSDOMFileUnsafely(JSC::JSGlobalObject* lexicalGlobalObject, void* ptr)
{
    auto* globalObject = defaultGlobalObject(lexicalGlobalObject);
    auto& vm = JSC::getVM(globalObject);
    auto* structure = globalObject->JSDOMFileStructure();
    return JSValue::encode(WebCore::JSBlob::create(vm, globalObject, structure, ptr));
}

} // namespace Bun
